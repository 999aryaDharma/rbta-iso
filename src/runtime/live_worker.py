"""Thread live worker yang menjalankan siklus ingestion di dalam proses FastAPI.

Keputusan desain (dikunci 2026-09-29):
- Worker adalah satu daemon thread milik lifespan proses backend. Tanpa proses
  terpisah dan tanpa IPC; RLock service sudah menyerialkan semua mutasi.
- Batasan: tepat satu proses backend. uvicorn multi-worker akan menjalankan satu
  thread per proses dan TIDAK didukung (lock single-writer antar proses memang
  sengaja tidak dikerjakan).
- Nonaktif secara default (RBTA_LIVE_WORKER_ENABLED=true untuk mengaktifkan) agar
  operasi replay/demo biasa tidak terpengaruh.
"""

from datetime import datetime, timezone
import logging
import os
import random
import threading
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional, Union

from src.runtime.durable_state import compute_derivation_hash
from src.runtime.service import LiveRBTAService

logger = logging.getLogger(__name__)

_JOIN_TIMEOUT_SEC = 30.0

# Batas atas exponential backoff di antara siklus ingestion yang gagal.
_BACKOFF_MAX_SEC = 300.0

# Handle lock state level OS yang hidup selama proses berjalan (ditahan sampai proses
# berhenti untuk menjamin hanya ada satu writer live; hanya dilepas lebih awal di test
# lewat release_state_lock).
_STATE_LOCK_HANDLES: list = []

# Path file lock (str) -> handle terbuka, dipakai oleh release_state_lock.
_STATE_LOCK_PATHS: Dict[str, Any] = {}


def worker_enabled_from_env(env_map: Mapping[str, str]) -> bool:
    """Apakah thread live worker diaktifkan lewat environment."""
    return str(env_map.get("RBTA_LIVE_WORKER_ENABLED", "false")).strip().lower() == "true"


def drain_on_stop_from_env(env_map: Mapping[str, str]) -> bool:
    """Apakah shutdown worker menguras bucket yang masih terbuka (default false).

    Drain adalah operasi decommission yang eksplisit, bukan jalur shutdown normal:
    pada restart biasa bucket terbuka tetap tersimpan di state durable.
    """
    return str(env_map.get("RBTA_LIVE_WORKER_DRAIN_ON_STOP", "false")).strip().lower() == "true"


def acquire_state_lock(state_path: Any):
    """Tahan lock eksklusif level OS untuk ``<state>.lock`` (langsung gagal bila sudah dipegang).

    Lock ditahan selama proses hidup (handle disimpan di :data:`_STATE_LOCK_HANDLES` dan
    tidak pernah dilepas, kecuali di test lewat :func:`release_state_lock`) supaya paling
    banyak satu proses backend yang menulis state runtime live.

    Raises
    ------
    RuntimeError
        Bila writer live lain sudah memegang lock.
    """
    lock_path = Path(str(state_path) + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = None
    try:
        handle = open(lock_path, "a+b")
        handle.seek(0, 2)
        if handle.tell() == 0:
            handle.write(b"\x00")
            handle.flush()
        handle.seek(0)
        if os.name == "nt":
            import msvcrt

            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise RuntimeError(
                    f"Live state '{state_path}' is locked: another live writer holds "
                    f"'{lock_path}'. Refusing to start a second live writer."
                ) from exc
        else:
            import fcntl

            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise RuntimeError(
                    f"Live state '{state_path}' is locked: another live writer holds "
                    f"'{lock_path}'. Refusing to start a second live writer."
                ) from exc
    except BaseException:
        if handle is not None:
            try:
                handle.close()
            except OSError:
                pass
        raise
    _STATE_LOCK_HANDLES.append(handle)
    _STATE_LOCK_PATHS[str(lock_path)] = handle
    return handle


def release_state_lock(state_path: Any) -> bool:
    """Lepaskan lock yang diambil lewat :func:`acquire_state_lock` (best effort).

    Unlock, tutup, dan lupakan handle registry untuk ``<state>.lock``. Produksi tidak
    pernah memanggil ini (lock berlaku selama proses hidup); fungsi ini ada agar test
    bisa melepas dan mengambil ulang lock. Tidak pernah error: True bila lock yang
    dipegang berhasil dilepas, False bila tidak ada yang dipegang.
    """
    lock_path = str(Path(str(state_path) + ".lock"))
    handle = _STATE_LOCK_PATHS.pop(lock_path, None)
    if handle is None:
        return False
    try:
        try:
            if os.name == "nt":
                import msvcrt

                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
            else:
                import fcntl

                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
        finally:
            try:
                handle.close()
            except OSError:
                pass
    finally:
        try:
            _STATE_LOCK_HANDLES.remove(handle)
        except ValueError:
            pass
    return True


def poll_interval_from_env(env_map: Mapping[str, str]) -> float:
    """Jeda antar siklus ingestion dalam detik (default 5.0)."""
    try:
        return max(0.1, float(env_map.get("RBTA_LIVE_POLL_INTERVAL_SEC", "5.0")))
    except (TypeError, ValueError):
        return 5.0


class LiveWorker:
    """Menjalankan siklus LiveIngestionCoordinator di thread latar belakang.

    Siklus yang gagal dicatat (last_error, consecutive_failures) dan worker tetap jalan:
    coordinator hanya meng-commit cursor transport saat berhasil, jadi siklus yang gagal
    tidak pernah memajukan state.
    """

    def __init__(
        self,
        service: LiveRBTAService,
        coordinator: Any,
        poll_interval: float = 5.0,
        drain_on_stop: bool = False,
        sleep_fn: Optional[Callable[[float], None]] = None,
        model_override: Optional[Union[bool, str]] = None,
        derivation_override: Optional[Union[bool, str]] = None,
    ) -> None:
        self.service = service
        self.coordinator = coordinator
        self.poll_interval = max(0.01, float(poll_interval))
        self.drain_on_stop = drain_on_stop
        self._sleep_fn = sleep_fn
        # Nilai override sekali pakai yang diteruskan dari env_map bootstrap
        # (None -> pakai os.environ saat pinning, agar pemanggil yang hanya mengatur
        # environment proses tetap berfungsi).
        self.model_override = model_override
        self.derivation_override = derivation_override
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._guard = threading.Lock()
        self._state_lock = threading.Lock()
        self.cycles_completed = 0
        self.consecutive_failures = 0
        self.last_error: Optional[str] = None
        self.last_cycle_at: Optional[str] = None

    def start(self) -> bool:
        """Jalankan thread worker. False bila sudah berjalan."""
        with self._guard:
            if self._thread is not None and self._thread.is_alive():
                return False
            self._stop_event.clear()
            self._pin_model_version()
            self._thread = threading.Thread(
                target=self._run, name="rbta-live-worker", daemon=True
            )
            self._thread.start()
            return True

    def stop(self, drain: Optional[bool] = None) -> None:
        """Hentikan thread worker (idempoten) dan opsional menguras bucket.

        Drain bersifat kooperatif: hanya dijalankan setelah thread worker selesai.
        Bila thread masih hidup setelah batas waktu join, drain dilewati dengan peringatan
        agar tidak balapan dengan siklus yang sedang berjalan.
        """
        with self._guard:
            self._stop_event.set()
            thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout=_JOIN_TIMEOUT_SEC)
            if thread.is_alive():
                logger.warning(
                    "Live worker thread still alive after %.1fs join; "
                    "skipping drain to avoid racing an active cycle",
                    _JOIN_TIMEOUT_SEC,
                )
                return
        if drain if drain is not None else self.drain_on_stop:
            self.service.shutdown(drain=True)

    def is_alive(self) -> bool:
        """Apakah thread worker sedang berjalan."""
        with self._guard:
            return self._thread is not None and self._thread.is_alive()

    def status(self) -> Dict[str, Any]:
        """Snapshot operasional untuk API status live yang read-only."""
        with self._state_lock:
            return {
                "alive": self.is_alive(),
                "cycles_completed": self.cycles_completed,
                "consecutive_failures": self.consecutive_failures,
                "last_error": self.last_error,
                "last_cycle_at": self.last_cycle_at,
            }

    def _pin_model_version(self) -> None:
        """Catat versi model scoring beku untuk sesi live ini.

        Versi yang sudah di-pin sebelumnya dan berbeda dari pipeline saat ini menolak startup
        (model basi langsung gagal), kecuali operator memberi override sekali pakai yang nilainya
        sama dengan versi saat ini (``RBTA_LIVE_MODEL_OVERRIDE=<version>``) atau service membawa
        ``run_id`` baru. Metadata ``model_version`` yang tidak ada adalah error keras: worker tidak
        pernah fallback ke ``"unknown"``.
        """
        pipeline = getattr(self.service, "scoring_pipeline", None)
        metadata = getattr(pipeline, "metadata", None)
        version = metadata.get("model_version") if isinstance(metadata, dict) else None
        if not version:
            raise RuntimeError(
                "Live worker requires scoring pipeline metadata with a non-empty "
                "'model_version'; refusing to start without a pinned model version."
            )
        version = str(version)
        source_state = self.service.get_live_source_state()
        old_pin = source_state.get("live_model_version")
        current_run = getattr(self.service, "run_id", None)
        old_run = source_state.get("live_run_id")
        self._reject_on_mismatch(
            kind="model",
            pinned=old_pin,
            current=version,
            override_raw=self.model_override,
            env_name="RBTA_LIVE_MODEL_OVERRIDE",
            current_run=current_run,
            old_run=old_run,
        )
        repinned_derivation = self._check_derivation_hash(source_state, current_run, old_run)
        now = datetime.now(timezone.utc).isoformat()
        payload = {
            "live_model_version": version,
            "live_worker_started_at": now,
        }
        # Penanda waktu mulai pertama, ditulis tepat satu kali per file state.
        # Berbeda dengan live_worker_started_at (diperbarui setiap start), key ini hanya diisi
        # bila belum ada sehingga restart tidak pernah menimpa nilai aslinya.
        if "live_first_started_at" not in source_state:
            payload["live_first_started_at"] = now
        if current_run:
            payload["live_run_id"] = current_run
        prior = [
            e
            for e in (source_state.get("live_pin_history") or [])
            if isinstance(e, dict)
        ]
        if not prior or prior[-1].get("version") != version:
            prior.append({"version": version, "at": now})
            payload["live_pin_history"] = prior[-20:]
        if repinned_derivation is not None:
            base = payload.get("live_pin_history", prior)
            base.append({"kind": "derivation", "value": repinned_derivation, "at": now})
            payload["live_pin_history"] = base[-20:]
        self.service.update_live_source_state(payload)
        logger.info("Live worker pinned scoring model version: '%s'", version)

    @staticmethod
    def _resolve_override(raw: Any, env_name: str) -> Optional[str]:
        """Nilai override mentah: nilai dari constructor diutamakan, selain itu os.environ."""
        value = raw if raw is not None else os.environ.get(env_name)
        if value is None or value is False:
            return None
        text = str(value).strip()
        return text or None

    def _reject_on_mismatch(
        self,
        *,
        kind: str,
        pinned: Any,
        current: str,
        override_raw: Any,
        env_name: str,
        current_run: Any,
        old_run: Any,
    ) -> bool:
        """Langsung gagal bila pin sudah basi; override dengan nilai persis atau run baru diizinkan.

        Override bersifat sekali pakai dan terikat versi: harus sama dengan nilai target saat ini,
        bukan ``"true"`` sembarangan. Override yang diisi tapi salah akan error alih-alih diabaikan
        (gagal tertutup). True bila startup boleh lanjut.
        """
        if not pinned or pinned == current:
            return True
        new_run = bool(current_run) and current_run != old_run
        override = self._resolve_override(override_raw, env_name)
        if override is not None and override == current:
            logger.warning(
                "Live %s override accepted for target '%s' via %s; re-pinning.",
                kind,
                current,
                env_name,
            )
            return True
        if new_run:
            return True
        label = (
            f"pinned '{pinned}' in source state vs current '{current}'"
            if kind == "model"
            else f"stored '{pinned}' in source state vs current '{current}'"
        )
        noun = "model version" if kind == "model" else "derivation config"
        hint = f"set {env_name}='{current}' to override explicitly"
        if override is not None:
            raise RuntimeError(
                f"Live {noun} mismatch: {label}. Refusing to start; "
                f"provided {env_name} value did not match '{current}'. "
                f"To override, {hint} or restart with a new run_id."
            )
        raise RuntimeError(
            f"Live {noun} mismatch: {label}. Refusing to start; "
            f"{hint} or restart with a new run_id."
        )

    def _check_derivation_hash(
        self, source_state: Dict[str, Any], current_run: Any, old_run: Any
    ) -> Optional[str]:
        """Tolak startup bila konfigurasi derivasi berubah; simpan baseline bila belum ada.

        Gagal tertutup: hash yang tidak bisa dihitung langsung error di sini dan tidak pernah
        ditelan oleh worker.

        Mengembalikan hash yang di-pin ulang bila ketidakcocokan tersimpan-vs-sekarang ditoleransi
        (override nilai persis atau run_id baru) dan baseline tersimpan sudah ditulis ulang, selain
        itu None. Pemanggil mencatat nilai non-None di ``live_pin_history`` agar restart berikutnya
        tanpa override berhasil terhadap baseline yang baru.
        """
        state_manager = self.service.state_manager
        stored = state_manager.get_derivation_hash()
        current = compute_derivation_hash()
        self._reject_on_mismatch(
            kind="derivation",
            pinned=stored,
            current=current,
            override_raw=self.derivation_override,
            env_name="RBTA_LIVE_DERIVATION_OVERRIDE",
            current_run=current_run,
            old_run=old_run,
        )
        if not stored:
            state_manager.set_derivation_hash(current)
            return None
        if stored != current:
            # Ketidakcocokan sudah ditoleransi di atas (override diterima atau run baru):
            # pin ulang baseline agar restart tanpa override berhasil.
            state_manager.set_derivation_hash(current)
            return current
        return None

    def _backoff_delay(self) -> float:
        """Exponential backoff dengan jitter setelah siklus gagal berturut-turut.

        Tumbuh dari interval poll dasar (``base * 2**(failures-1)``) sampai batas 5 menit;
        jitter proporsional kecil mencegah retry yang serempak.
        """
        base = max(0.01, float(self.poll_interval))
        failures = max(1, self.consecutive_failures)
        delay = min(base * (2.0 ** (failures - 1)), _BACKOFF_MAX_SEC)
        jitter = random.uniform(0.0, min(1.0, delay * 0.1))
        return delay + jitter

    def _sleep(self, delay: float) -> None:
        """Tunggu di antara siklus pada stop event (atau sleep_fn yang di-inject apa adanya)."""
        (self._sleep_fn or self._stop_event.wait)(delay)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.coordinator.run_cycle()
            except Exception as exc:
                logger.error("Live ingestion cycle failed: %s", exc)
                with self._state_lock:
                    self.consecutive_failures += 1
                    self.last_error = str(exc)
                    delay = self._backoff_delay()
                self._sleep(delay)
                continue
            with self._state_lock:
                self.cycles_completed += 1
                self.consecutive_failures = 0
                self.last_cycle_at = datetime.now(timezone.utc).isoformat()
            self._sleep(self.poll_interval)
