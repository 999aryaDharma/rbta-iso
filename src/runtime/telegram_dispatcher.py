"""Dispatcher Telegram live yang berdiri sendiri.

Membaca MetaAlert terskor dengan ``action == "ESCALATE"`` dari outbox service dan
mengirimkannya hanya lewat Telegram (keputusan terkunci — tidak ada kanal lain). Bila
berhasil, item di-commit lewat ``service.commit_outbox`` (durable di dalam service); bila
gagal, item tetap di outbox — at-least-once lintas restart (kunci idempotensi
``"{run_id}:{meta_id}"``). Mode efektifnya ``live`` (kredensial ada), ``dry_run``
(``dry_run=True`` eksplisit atau ``RBTA_TELEGRAM_DRY_RUN=true`` — item di-commit dan dicatat
tanpa dikirim), atau ``hold`` (tanpa kredensial dan tanpa flag dry-run — item dilewati dan
outbox dipertahankan).

Format pesan memakai :func:`src.runtime.telegram_formatter.format_telegram_alert` (format
kanonis yang sama dengan sink Telegram tertunda milik replay), yang sudah menampilkan
decision dan action di field terpisah.

Sender di-inject (``Callable[[dict], None]``, melempar error bila gagal) sehingga dispatcher
bisa diuji tanpa akses jaringan sungguhan. Sender default adalah placeholder yang melempar
error; pengiriman HTTP sungguhan dipasang lewat make_telegram_sender.

Kepemilikan thread: dispatcher menjalankan thread polling sendiri dan tidak pernah
menyentuh internal ``LiveWorker``; ia hanya memanggil kontrak outbox publik
(``get_outbox`` / ``commit_outbox``).

Pemasangan di lifespan:

    dispatcher = TelegramDispatcher(live_service, sender=make_telegram_sender())
    dispatcher.start()    # saat startup lifespan FastAPI, setelah worker start
    dispatcher.stop()     # saat shutdown lifespan, sebelum worker stop
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Deque, Dict, List, Optional, Protocol, Set

from src.runtime.telegram_formatter import format_telegram_alert

logger = logging.getLogger(__name__)

# Token pernah muncul di path URL DEBUG urllib3 (bot token ada di URL
# api.telegram.org/bot<token>/...), sehingga level DEBUG modul ini bocor.
# Kunci di WARNING pada import-time agar tidak ada auto-log URL bertoken.
logging.getLogger("urllib3").setLevel(logging.WARNING)

BOT_TOKEN_ENV = "RBTA_TELEGRAM_BOT_TOKEN"
CHAT_ID_ENV = "RBTA_TELEGRAM_CHAT_ID"
NOTIFY_MAX_AGE_ENV = "RBTA_TELEGRAM_NOTIFY_MAX_AGE_SEC"
DRY_RUN_ENV = "RBTA_TELEGRAM_DRY_RUN"
MIN_INTERVAL_ENV = "RBTA_TELEGRAM_MIN_INTERVAL_SEC"
DEFAULT_NOTIFY_MAX_AGE_SEC = 3600.0
# Jeda default antar pengiriman. Grup Telegram membatasi ~20 pesan/menit, jadi naikkan
# RBTA_TELEGRAM_MIN_INTERVAL_SEC ke >= 3.0 untuk pengiriman ke grup.
MIN_SEND_INTERVAL_SEC = 1.0
MAX_RETRY_AFTER_SEC = 60.0
MAX_SENT_KEYS = 10000
MAX_DRY_RUN_PAYLOADS = 50
_CHAIN_SCAN_DEPTH = 8


class OutboxReader(Protocol):
    """Kontrak outbox publik minimal yang dipakai dari service runtime."""

    def get_outbox(self) -> list: ...
    def commit_outbox(self, meta_ids: List[int]) -> int: ...


SenderFn = Callable[[Dict[str, Any]], None]


@dataclass
class DispatchResult:
    """Jumlah hasil satu putaran dispatch atas snapshot outbox."""

    sent: int = 0
    failed: int = 0
    skipped: int = 0
    dry_run: int = 0
    duplicate_skipped: int = 0
    suppressed_historical: int = 0
    attempts: int = 0
    sleeps_sec: List[float] = field(default_factory=list)


def _http_status_of(exc: BaseException) -> Optional[int]:
    """Ambil kode status HTTP tanpa menyentuh isi URL/body."""
    current: Optional[BaseException] = exc
    for _ in range(_CHAIN_SCAN_DEPTH):
        if current is None:
            break
        for attr in ("http_status", "status_code"):
            value = getattr(current, attr, None)
            if isinstance(value, int):
                return value
        response = getattr(current, "response", None)
        status = getattr(response, "status_code", None)
        if isinstance(status, int):
            return status
        current = current.__cause__ or current.__context__
    return None


def _retry_after_of(exc: BaseException) -> Optional[float]:
    """Ambil jeda Retry-After dalam detik, dibatasi oleh pemanggil.

    Header ``Retry-After`` diutamakan; body 429 Telegram membawa ``parameters.retry_after``
    sebagai fallback (dibaca tanpa dicatat ke log).
    """
    current: Optional[BaseException] = exc
    for _ in range(_CHAIN_SCAN_DEPTH):
        if current is None:
            break
        for attr in ("retry_after_sec", "retry_after"):
            value = getattr(current, attr, None)
            if isinstance(value, (int, float)):
                return max(0.0, float(value))
        response = getattr(current, "response", None)
        headers = getattr(response, "headers", None)
        if headers:
            try:
                raw = headers.get("Retry-After")
            except Exception:
                raw = None
            if raw is not None:
                try:
                    return max(0.0, float(str(raw).strip()))
                except (TypeError, ValueError):
                    pass
        else:
            raw = None
        if raw is None and response is not None:
            try:
                body = response.json()  # type: ignore[attr-defined]
            except Exception:
                body = None
            if isinstance(body, dict):
                params = body.get("parameters")
                if isinstance(params, dict):
                    fallback = params.get("retry_after")
                    if isinstance(fallback, (int, float)):
                        return max(0.0, float(fallback))
        current = current.__cause__ or current.__context__
    return None


def _sanitize_send_error(exc: BaseException) -> str:
    """Tampilkan kegagalan kirim tanpa URL, body, atau isi kredensial."""
    status = _http_status_of(exc)
    if status is not None:
        return f"{type(exc).__name__} HTTP {status}"
    return type(exc).__name__


def _resolve_notify_max_age_sec(raw: Optional[float]) -> Optional[float]:
    if raw is not None:
        return max(0.0, float(raw))
    env_raw = os.environ.get(NOTIFY_MAX_AGE_ENV)
    if env_raw is not None:
        try:
            return max(0.0, float(env_raw))
        except (TypeError, ValueError):
            logger.warning(
                "Invalid %s=%r; falling back to default %.0f",
                NOTIFY_MAX_AGE_ENV,
                env_raw,
                DEFAULT_NOTIFY_MAX_AGE_SEC,
            )
    return DEFAULT_NOTIFY_MAX_AGE_SEC


def _resolve_dry_run(explicit: Optional[bool]) -> bool:
    """``dry_run`` eksplisit diutamakan; selain itu RBTA_TELEGRAM_DRY_RUN=true."""
    if explicit is not None:
        return bool(explicit)
    return os.environ.get(DRY_RUN_ENV, "false").strip().lower() == "true"


def _resolve_min_interval_sec(raw: Optional[float]) -> float:
    """``min_interval_sec`` eksplisit diutamakan; selain itu env; selain itu default 1.0."""
    if raw is not None:
        return max(0.0, float(raw))
    env_raw = os.environ.get(MIN_INTERVAL_ENV)
    if env_raw is not None:
        try:
            return max(0.0, float(env_raw))
        except (TypeError, ValueError):
            logger.warning(
                "Invalid %s=%r; falling back to default %.1f",
                MIN_INTERVAL_ENV,
                env_raw,
                MIN_SEND_INTERVAL_SEC,
            )
    return MIN_SEND_INTERVAL_SEC


def _default_sender(_payload: Dict[str, Any]) -> None:
    raise RuntimeError(
        "No Telegram sender configured: pass sender= explicitly or wire "
        "the real HTTP sender at lifespan integration time."
    )


def make_telegram_sender(
    bot_token: str,
    timeout_sec: float = 10.0,
    session: Any = None,
) -> SenderFn:
    """Bangun sender Telegram Bot API sungguhan (sendMessage).

    Melempar error bila transport gagal atau API menjawab ``ok: false``. Kredensial tidak
    pernah dicatat. Jaringan baru dipakai saat callable yang dikembalikan dipanggil oleh
    thread dispatcher.
    """
    import requests

    http = session or requests

    def send(payload: Dict[str, Any]) -> None:
        chat_id = payload.get("chat_id")
        if not chat_id:
            raise RuntimeError("Telegram payload has no chat_id; refusing to send")
        try:
            resp = http.post(
                f"https://api.telegram.org/bot{bot_token}/sendMessage",
                json={
                    "chat_id": chat_id,
                    "text": payload["message"],
                    "parse_mode": payload.get("parse_mode", "HTML"),
                },
                timeout=timeout_sec,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            status = _http_status_of(exc)
            retry_after = _retry_after_of(exc)
            safe = _sanitize_send_error(exc)
            err = RuntimeError(f"Telegram Bot API request failed: {safe}")
            if status is not None:
                err.http_status = status  # type: ignore[attr-defined]
            if retry_after is not None:
                err.retry_after_sec = retry_after  # type: ignore[attr-defined]
            # Rantai asli (URL berisi bot token) tidak boleh terbawa di __cause__/__traceback__ —
            # pesan `safe` sudah cukup untuk debug.
            raise err from None
        if not isinstance(data, dict) or not data.get("ok"):
            raise RuntimeError(
                f"Telegram Bot API rejected sendMessage for meta_id={payload.get('meta_id')}"
            )

    return send


class TelegramDispatcher:
    """Polling outbox service dan kirim item ESCALATE lewat Telegram.

    Prioritas penentuan waktu bootstrap untuk menahan alert historis: parameter constructor
    ``bootstrap_started_at`` bila diberikan, selain itu key ``live_first_started_at`` yang dibaca
    lazy dari ``service.get_live_source_state()`` (dijaga — method tidak ada, error, atau nilai
    yang tidak bisa di-parse dianggap None), selain itu None.

    Mode pengiriman efektif (``mode``): ``"live"`` bila kredensial dikonfigurasi, ``"dry_run"``
    bila ``dry_run`` eksplisit atau ``RBTA_TELEGRAM_DRY_RUN=true``, selain itu ``"hold"`` (outbox
    dipertahankan, tidak ada yang dikirim maupun di-commit).
    """

    def __init__(
        self,
        service: OutboxReader,
        sender: Optional[SenderFn] = None,
        run_id: str = "live",
        bot_token: Optional[str] = None,
        chat_id: Optional[str] = None,
        max_attempts: int = 3,
        backoff_base_sec: float = 1.0,
        poll_interval_sec: float = 5.0,
        sleep_fn: Optional[Callable[[float], None]] = None,
        notify_max_age_sec: Optional[float] = None,
        bootstrap_started_at: Optional[datetime] = None,
        dry_run: Optional[bool] = None,
        monotonic_fn: Callable[[], float] = time.monotonic,
        min_interval_sec: Optional[float] = None,
    ) -> None:
        self._service = service
        self._sender = sender or _default_sender
        self._run_id = run_id
        self._bot_token = bot_token if bot_token is not None else os.environ.get(BOT_TOKEN_ENV)
        self._chat_id = chat_id if chat_id is not None else os.environ.get(CHAT_ID_ENV)
        self._dry_run = _resolve_dry_run(dry_run)
        self._max_attempts = max(1, max_attempts)
        self._backoff_base_sec = max(0.0, backoff_base_sec)
        self._poll_interval_sec = max(0.1, poll_interval_sec)
        self._stop_event = threading.Event()
        # None -> stop_event.wait yang bisa diinterupsi (pola worker); sleep_fn eksplisit
        # dipakai apa adanya (mis. probe di test).
        self._sleep = sleep_fn if sleep_fn is not None else self._stop_event.wait
        self._notify_max_age_sec = _resolve_notify_max_age_sec(notify_max_age_sec)
        if bootstrap_started_at is not None and bootstrap_started_at.tzinfo is None:
            bootstrap_started_at = bootstrap_started_at.replace(tzinfo=timezone.utc)
        self._bootstrap_started_at = bootstrap_started_at
        self._monotonic_fn = monotonic_fn
        self._min_interval_sec = _resolve_min_interval_sec(min_interval_sec)
        self._last_send_monotonic: Optional[float] = None
        self._sent_keys: Set[str] = set()
        self._sent_order: Deque[str] = deque()
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self.dry_run_payloads: List[Dict[str, Any]] = []
        self._sent_total = 0
        self._failed_total = 0
        self._suppressed_historical_total = 0
        self._dry_run_total = 0

    @property
    def enabled(self) -> bool:
        """True hanya bila bot token dan chat id sama-sama dikonfigurasi."""
        return bool(self._bot_token and self._chat_id)

    @property
    def mode(self) -> str:
        """Mode pengiriman efektif: ``live`` | ``dry_run`` | ``hold``.

        ``dry_run`` (flag eksplisit atau RBTA_TELEGRAM_DRY_RUN=true) mengalahkan kredensial;
        ``live`` butuh kredensial tanpa dry-run; selain itu ``hold`` — item dilewati, outbox
        dipertahankan, peringatan sekali per putaran.
        """
        if self._dry_run:
            return "dry_run"
        if self.enabled:
            return "live"
        return "hold"

    def status(self) -> Dict[str, Any]:
        """Counter dispatch kumulatif beserta mode efektif."""
        with self._lock:
            return {
                "sent_total": self._sent_total,
                "failed_total": self._failed_total,
                "suppressed_historical_total": self._suppressed_historical_total,
                "dry_run_total": self._dry_run_total,
                "mode": self.mode,
            }

    def _remember_sent_key(self, key: str) -> None:
        """Catat kunci idempotensi dengan eviction FIFO pada MAX_SENT_KEYS."""
        with self._lock:
            if key in self._sent_keys:
                return
            self._sent_keys.add(key)
            self._sent_order.append(key)
            while len(self._sent_keys) > MAX_SENT_KEYS:
                oldest = self._sent_order.popleft()
                self._sent_keys.discard(oldest)

    def _is_duplicate(self, key: str) -> bool:
        with self._lock:
            return key in self._sent_keys

    def _effective_bootstrap_started_at(self) -> Optional[datetime]:
        """Tentukan timestamp bootstrap dengan fallback lazy ke state.

        Prioritas: parameter constructor bila diberikan, selain itu key ``live_first_started_at``
        dari ``service.get_live_source_state()`` (dijaga — method tidak ada, error apa pun, state
        bukan dict, atau nilai yang tidak bisa di-parse dianggap None), selain itu None.
        """
        if self._bootstrap_started_at is not None:
            return self._bootstrap_started_at
        try:
            getter = getattr(self._service, "get_live_source_state", None)
            if not callable(getter):
                return None
            state = getter()
        except Exception:
            return None
        if not isinstance(state, dict):
            return None
        raw = state.get("live_first_started_at")
        if raw is None:
            return None
        if isinstance(raw, datetime):
            resolved = raw
        elif isinstance(raw, str):
            try:
                resolved = datetime.fromisoformat(raw)
            except (TypeError, ValueError):
                return None
        else:
            return None
        if resolved.tzinfo is None:
            resolved = resolved.replace(tzinfo=timezone.utc)
        return resolved

    def _is_historical(self, scored: Any) -> bool:
        """True bila item berakhir sebelum waktu bootstrap dikurangi toleransi.

        Penahanan berpatokan pada waktu BOOTSTRAP, bukan umur saat dikirim — gangguan di tengah run
        tidak boleh menelan ESCALATE yang masih baru. end_time yang tidak valid/tidak ada tidak
        pernah menahan.

        Batas desain: ESCALATE dengan ``end_time`` kurang dari ``notify_max_age_sec`` (default 3600
        detik) sebelum bootstrap tetap dikirim — hanya item yang benar-benar lebih tua yang ditahan.

        Bootstrap yang tidak diketahui (None) mengembalikan False di sini; pemanggil
        (``dispatch_once``) wajib gagal tertutup alih-alih mengirim.
        """
        bootstrap = self._effective_bootstrap_started_at()
        if bootstrap is None:
            return False
        if self._notify_max_age_sec is None:
            return False
        end_time = getattr(scored, "end_time", None)
        if not isinstance(end_time, datetime):
            return False
        if end_time.tzinfo is None:
            end_time = end_time.replace(tzinfo=timezone.utc)
        cutoff = bootstrap - timedelta(seconds=self._notify_max_age_sec)
        return end_time < cutoff

    def _record_notification(self, meta_id: Any, verdict: str) -> bool:
        """Catatan putusan pengiriman yang durable; satu-satunya sumber putusan.

        Memanggil ``state_manager.notification_add(meta_id, run_id, verdict)`` dengan verdict
        ``SENT`` / ``DRY_RUN`` / ``SUPPRESSED_HISTORICAL``. True bila tercatat atau bila method-nya
        tidak ada (hanya counter+log). False bila pemanggilan error; pemanggil harus melewati commit
        agar item tetap antre untuk putaran berikutnya.
        """
        record = getattr(
            getattr(self._service, "state_manager", None), "notification_add", None
        )
        if not callable(record):
            logger.debug(
                "notification_add unavailable; verdict=%s meta_id=%s (counter only)",
                verdict,
                getattr(meta_id, "meta_id", meta_id),
            )
            return True
        try:
            record(meta_id=int(meta_id), run_id=self._run_id, verdict=verdict)  # type: ignore[arg-type]
        except Exception:
            logger.debug(
                "notification_add failed for meta_id=%s verdict=%s",
                getattr(meta_id, "meta_id", meta_id),
                verdict,
            )
            return False
        return True

    def _build_payload(self, scored: Any) -> Dict[str, Any]:
        message = format_telegram_alert(scored, run_id=self._run_id)
        return {
            "meta_id": scored.meta_id,
            "idempotency_key": f"{self._run_id}:{scored.meta_id}",
            "run_id": self._run_id,
            "decision": scored.decision,
            "action": scored.action,
            "anomaly_score": round(float(scored.anomaly_score), 6),
            "threshold": round(float(scored.threshold_used), 6),
            "model_version": scored.model_version,
            "agent_id": scored.agent_id,
            "agent_name": scored.agent_name,
            "rule_group_primary": scored.rule_group_primary,
            "alert_count": scored.alert_count,
            "max_severity": scored.max_severity,
            "chat_id": self._chat_id,
            "message": message,
            "parse_mode": "HTML",
        }

    def _throttle_before_send(self, result: DispatchResult) -> None:
        if self._min_interval_sec <= 0.0 or self._last_send_monotonic is None:
            return
        try:
            elapsed = self._monotonic_fn() - self._last_send_monotonic
        except Exception:
            return
        wait = self._min_interval_sec - elapsed
        if wait > 0:
            result.sleeps_sec.append(wait)
            self._sleep(wait)

    def _send_with_retry(self, payload: Dict[str, Any], result: DispatchResult) -> bool:
        attempt = 0
        while attempt < self._max_attempts:
            attempt += 1
            result.attempts += 1
            try:
                self._sender(payload)
                return True
            except Exception as exc:
                logger.warning(
                    "Telegram send failed for %s (attempt %d/%d): %s",
                    payload["idempotency_key"],
                    attempt,
                    self._max_attempts,
                    _sanitize_send_error(exc),
                )
                if attempt < self._max_attempts:
                    if _http_status_of(exc) == 429:
                        retry_after = _retry_after_of(exc)
                        if retry_after is not None:
                            delay = min(retry_after, MAX_RETRY_AFTER_SEC)
                        else:
                            delay = self._backoff_base_sec * (2 ** (attempt - 1))
                    else:
                        delay = self._backoff_base_sec * (2 ** (attempt - 1))
                    result.sleeps_sec.append(delay)
                    self._sleep(delay)
        return False

    def dispatch_once(self) -> DispatchResult:
        """Satu putaran atas snapshot outbox saat ini.

        Hanya item ``action == "ESCALATE"`` yang dikirim. Pengiriman yang berhasil di-commit lewat
        ``service.commit_outbox``; yang gagal tetap antre (at-least-once lintas restart: restart bisa
        mengirim ulang item yang terkirim tetapi commit-nya hilang). Item yang ``end_time``-nya lebih
        awal dari waktu bootstrap dikurangi ``notify_max_age_sec`` ditahan dari pengiriman tetapi tetap
        di-commit untuk menguras backlog bootstrap. Bootstrap yang tidak diketahui (tidak ada parameter
        eksplisit maupun state ``live_first_started_at``) gagal tertutup: item dilewati untuk putaran ini,
        tetap di outbox (TIDAK di-commit), dan satu WARNING dicatat per putaran. Mode hold (tanpa kredensial
        dan tanpa flag dry-run) juga melewati tanpa commit — outbox dipertahankan dan satu WARNING dicatat
        per putaran. Dry-run eksplisit menguras outbox: setiap item di-commit, kuncinya dicatat untuk dedup
        lintas putaran, dan payload-nya disimpan di buffer 50 terakhir sementara counter dry-run tetap akurat.
        Hasil akhir (sent, dry-run, suppressed) dicatat lewat ``state_manager.notification_add`` bila
        tersedia; pencatatan yang gagal membatalkan commit sehingga item tetap antre (failed += 1).
        """
        result = DispatchResult()
        snapshot = list(self._service.get_outbox())
        bootstrap = self._effective_bootstrap_started_at()
        mode = self.mode
        unknown_warned = False
        hold_warned = False
        for scored in snapshot:
            if scored.action != "ESCALATE":
                result.skipped += 1
                continue
            key = f"{self._run_id}:{scored.meta_id}"
            if self._is_duplicate(key):
                result.duplicate_skipped += 1
                # I/O disk di luar _lock: commit di sini, bukan di dalam lock.
                self._service.commit_outbox([scored.meta_id])
                continue
            if bootstrap is None:
                if not unknown_warned:
                    logger.warning(
                        "Telegram dispatcher fail-closed: unknown bootstrap, "
                        "deferring %d ESCALATE item(s) this pass (outbox retained)",
                        sum(1 for s in snapshot if s.action == "ESCALATE"),
                    )
                    unknown_warned = True
                result.skipped += 1
                continue
            if self._is_historical(scored):
                if not self._record_notification(scored.meta_id, "SUPPRESSED_HISTORICAL"):
                    with self._lock:
                        self._failed_total += 1
                    result.failed += 1
                    continue
                result.suppressed_historical += 1
                with self._lock:
                    self._suppressed_historical_total += 1
                self._service.commit_outbox([scored.meta_id])
                logger.info(
                    "Telegram dispatcher suppressed historical %s (before bootstrap)",
                    key,
                )
                continue
            if mode == "hold":
                if not hold_warned:
                    logger.warning(
                        "Telegram dispatcher holding outbox: credentials missing "
                        "and RBTA_TELEGRAM_DRY_RUN not set; %d ESCALATE item(s) "
                        "retained this pass",
                        sum(1 for s in snapshot if s.action == "ESCALATE"),
                    )
                    hold_warned = True
                result.skipped += 1
                continue
            if mode == "dry_run":
                payload = self._build_payload(scored)
                if not self._record_notification(scored.meta_id, "DRY_RUN"):
                    with self._lock:
                        self._failed_total += 1
                    result.failed += 1
                    continue
                result.dry_run += 1
                with self._lock:
                    self._dry_run_total += 1
                self._remember_sent_key(key)
                self.dry_run_payloads.append(payload)
                del self.dry_run_payloads[:-MAX_DRY_RUN_PAYLOADS]
                self._service.commit_outbox([scored.meta_id])
                logger.info("Telegram dispatcher dry-run for %s (no send)", key)
                continue
            payload = self._build_payload(scored)
            self._throttle_before_send(result)
            if self._send_with_retry(payload, result):
                if not self._record_notification(scored.meta_id, "SENT"):
                    with self._lock:
                        self._failed_total += 1
                    result.failed += 1
                    continue
                self._remember_sent_key(key)
                with self._lock:
                    self._sent_total += 1
                try:
                    self._last_send_monotonic = self._monotonic_fn()
                except Exception:
                    self._last_send_monotonic = None
                self._service.commit_outbox([scored.meta_id])
                result.sent += 1
            else:
                with self._lock:
                    self._failed_total += 1
                result.failed += 1
        return result

    def start(self) -> None:
        """Jalankan thread polling latar belakang (idempoten)."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._run_loop, name="telegram-dispatcher", daemon=True
            )
            self._thread.start()

    def stop(self, timeout_sec: float = 10.0) -> None:
        """Hentikan thread latar belakang (idempoten)."""
        with self._lock:
            thread = self._thread
        self._stop_event.set()
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout_sec)
        with self._lock:
            self._thread = None

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.dispatch_once()
            except Exception as exc:
                logger.error("Telegram dispatcher pass failed: %s", exc)
            self._stop_event.wait(self._poll_interval_sec)
