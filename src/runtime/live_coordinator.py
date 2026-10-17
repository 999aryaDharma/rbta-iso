"""Coordinator ingestion live: polling cepat data terbaru, scan rekonsiliasi, dan ingestion durable."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

from src.contracts.raw_alert import CanonicalRawAlert
from src.contracts.scored_meta_alert import ScoredMetaAlert
from src.rbta.engine import RBTAInvariantError
from src.rbta.temporal_state import TemporalStateError
from src.runtime.live_source import WazuhIndexerLivePoller
from src.runtime.order_buffer import OrderBuffer, partition_unseen
from src.runtime.raw_evidence import RawEvidenceConflictError, RawEvidenceIntegrityError
from src.runtime.service import LiveRBTAService

logger = logging.getLogger(__name__)

# Kegagalan per record yang deterministik dikarantina secara durable (kebijakan QUARANTINE).
# engine.process atomik untuk kasus ini: tidak ada state commit yang berubah dan ID alert
# tidak pernah ditandai seen, sehingga retry akan menghasilkan error yang sama.
_QUARANTINE_ERRORS = (
    RawEvidenceConflictError,
    RawEvidenceIntegrityError,
    RBTAInvariantError,
    TemporalStateError,
)

# Circuit breaker: hentikan siklus alih-alih menyerap korupsi yang sistemik.
_QUARANTINE_BREAKER_FRACTION = 0.01
_QUARANTINE_BREAKER_ABSOLUTE = 100

# Timestamp event yang melewati now + skew ini dianggap dari masa depan (clock skew
# atau event time rusak) dan tidak boleh menggeser newest_ingested_event_time.
_FUTURE_EVENT_SKEW = timedelta(minutes=5)


@dataclass(frozen=True)
class LiveCycleResult:
    """Metrik observability operasional untuk satu siklus ingestion live."""

    fast_candidates: int
    recent_reconciliation_candidates: int
    full_reconciliation_candidates: int
    submitted_candidates: int
    duplicate_noops: int
    processed_new_ids: int
    failures: int
    new_scored_meta_alerts: int
    quarantined: int = 0
    skipped_quarantined: int = 0

    @property
    def reconciliation_candidates(self) -> int:
        """Jumlah agregat kandidat rekonsiliasi (dipertahankan untuk kompatibilitas)."""
        return self.recent_reconciliation_candidates + self.full_reconciliation_candidates


class LiveIngestionCoordinator:
    """Mengoordinasikan polling cepat data terbaru, scan rekonsiliasi terbaru, dan sweep seluruh retensi.

    Parameters
    ----------
    service : LiveRBTAService
        Service runtime live stateful tujuan.
    poller : WazuhIndexerLivePoller | None
        Sumber poller Wazuh Indexer.
    fast_poll_interval : timedelta
        Jeda antar siklus polling cepat (default 5 detik).
    recent_reconciliation_interval : timedelta
        Jeda antar scan rekonsiliasi terbaru (default 5 menit).
    full_reconciliation_interval : timedelta
        Jeda antar sweep menyeluruh seluruh retensi (default 1 jam).
    recent_reconciliation_days : int
        Jumlah index harian terbaru yang di-scan saat rekonsiliasi terbaru (default 2).
    order_buffer_enabled : bool
        Bila True, kandidat ditahan di OrderBuffer dan hanya yang dilepas oleh
        watermark / max_hold yang di-ingest, sehingga celah urutan antar siklus
        (alert rekonsiliasi yang terlambat vs alert fast-poll) tertutup. Default False,
        yang mempertahankan perilaku lama (langsung ingest).
    order_buffer_hold_window : timedelta
        Window tahan event-time untuk watermark buffer (default 30 detik).
    order_buffer_max_hold : timedelta
        Batas tahan wall-clock sebelum dilepas paksa (default 5 menit).
    order_buffer_max_items : int
        Kapasitas buffer; bila penuh memicu backpressure, tidak pernah membuang alert.
    breaker_ack : str | None
        Konfirmasi operator untuk breaker yang sedang ter-latch. Server meneruskan
        ``RBTA_QUARANTINE_BREAKER_ACK`` ke sini; nilai yang cocok dengan ``trip_id``
        yang ter-latch akan membersihkan latch dan siklus berjalan lagi, nilai lain
        tetap menahan. Default None (tanpa konfirmasi).

    Perbedaan operasional
    ---------------------
    quarantine = satu record rusak yang terisolasi diserap dan siklus tetap berjalan
    (satu record buruk tidak membutakan ingestion). breaker-latch = korupsi sistemik
    menghentikan siklus dan menyimpan latch ``breaker_tripped`` ke source state; setiap
    siklus berikutnya langsung error — tanpa polling, ingest, atau commit — sampai
    operator mengonfirmasi dengan ``trip_id`` yang cocok.
    """

    def __init__(
        self,
        service: LiveRBTAService,
        poller: Optional[WazuhIndexerLivePoller] = None,
        fast_poll_interval: timedelta = timedelta(seconds=5),
        recent_reconciliation_interval: timedelta = timedelta(minutes=5),
        full_reconciliation_interval: timedelta = timedelta(hours=1),
        recent_reconciliation_days: int = 2,
        reconciliation_interval: Optional[timedelta] = None,
        reconciliation_days: Optional[int] = None,
        order_buffer_enabled: bool = False,
        order_buffer_hold_window: timedelta = timedelta(seconds=30),
        order_buffer_max_hold: timedelta = timedelta(minutes=5),
        order_buffer_max_items: int = 1000,
        breaker_ack: Optional[str] = None,
        live_archive_enabled: Optional[bool] = None,
        live_archive_dir: Optional[Union[str, Path]] = None,
    ) -> None:
        self.service: LiveRBTAService = service
        self.poller: WazuhIndexerLivePoller = poller or WazuhIndexerLivePoller()
        self.fast_poll_interval: timedelta = fast_poll_interval
        self.recent_reconciliation_interval: timedelta = (
            reconciliation_interval or recent_reconciliation_interval
        )
        self.full_reconciliation_interval: timedelta = full_reconciliation_interval
        self.recent_reconciliation_days: int = (
            reconciliation_days or recent_reconciliation_days
        )
        self.order_buffer: Optional[OrderBuffer] = (
            OrderBuffer(
                hold_window=order_buffer_hold_window,
                max_hold=order_buffer_max_hold,
                max_items=order_buffer_max_items,
            )
            if order_buffer_enabled
            else None
        )
        self.breaker_ack: Optional[str] = breaker_ack

        # Arsip JSONL mentah (best effort) untuk alert yang di-ingest dari live.
        # Default nonaktif agar jalur replay/demo tidak terpengaruh; aktifkan lewat
        # RBTA_LIVE_ARCHIVE_ENABLED=1 (direktori lewat RBTA_LIVE_ARCHIVE_DIR).
        if live_archive_enabled is None:
            live_archive_enabled = os.environ.get(
                "RBTA_LIVE_ARCHIVE_ENABLED", ""
            ).strip().lower() in ("1", "true", "yes", "on")
        self.live_archive_enabled: bool = bool(live_archive_enabled)
        if live_archive_dir is None:
            env_dir = os.environ.get("RBTA_LIVE_ARCHIVE_DIR", "").strip()
            live_archive_dir = env_dir if env_dir else "data/archive"
        self.live_archive_dir: Path = Path(live_archive_dir)

        # Pulihkan state cursor transport dari service.
        source_state = self.service.get_live_source_state()

        raw_cursor = source_state.get("recent_poll_cursor")
        self.recent_poll_cursor: Optional[datetime] = (
            datetime.fromisoformat(raw_cursor) if raw_cursor else None
        )

        raw_fast = source_state.get("last_fast_poll_at")
        self.last_fast_poll_at: Optional[datetime] = (
            datetime.fromisoformat(raw_fast) if raw_fast else None
        )

        raw_recent_recon = source_state.get("last_recent_reconciliation_at") or source_state.get(
            "last_reconciliation_at"
        )
        self.last_recent_reconciliation_at: Optional[datetime] = (
            datetime.fromisoformat(raw_recent_recon) if raw_recent_recon else None
        )

        raw_full_recon = source_state.get("last_full_reconciliation_at")
        self.last_full_reconciliation_at: Optional[datetime] = (
            datetime.fromisoformat(raw_full_recon) if raw_full_recon else None
        )

    def run_fast_poll(self, current_time: Optional[datetime] = None) -> List[CanonicalRawAlert]:
        """Jalankan jalur polling cepat memakai hint cursor poll saat ini."""
        now = current_time or datetime.now(timezone.utc)
        return self.poller.poll_recent(current_time=now, recent_poll_cursor=self.recent_poll_cursor)

    def run_recent_reconciliation(
        self,
        current_time: Optional[datetime] = None,
        days: Optional[int] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[CanonicalRawAlert]:
        """Jalankan scan rekonsiliasi pada index harian terbaru."""
        now = current_time or datetime.now(timezone.utc)
        n_days = days or self.recent_reconciliation_days
        return self.poller.poll_reconciliation(
            current_time=now,
            reconciliation_days=n_days,
            start_time=start_time,
            end_time=end_time,
        )

    def run_reconciliation(
        self,
        current_time: Optional[datetime] = None,
        days: Optional[int] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[CanonicalRawAlert]:
        """Alias run_recent_reconciliation, dipertahankan untuk kompatibilitas."""
        return self.run_recent_reconciliation(
            current_time=current_time,
            days=days,
            start_time=start_time,
            end_time=end_time,
        )

    def run_full_reconciliation(self, prefix: str = "wazuh-alerts-4.x-") -> List[CanonicalRawAlert]:
        """Jalankan rekonsiliasi seluruh retensi tanpa kehilangan data di semua index harian yang tersimpan.

        Cakupan index ketat: index yang ditemukan tetapi tidak tersedia langsung gagal,
        bukan diam-diam dilewati seolah hasilnya kosong.
        """
        return self.poller.poll_full_reconciliation(prefix=prefix, allow_unavailable=False)

    def run_cycle(
        self,
        current_time: Optional[datetime] = None,
        force_recent_reconciliation: bool = False,
        force_full_reconciliation: bool = False,
        force_reconciliation: bool = False,
    ) -> LiveCycleResult:
        """Jalankan satu siklus ingestion live yang terkoordinasi.

        1. Jalankan sweep seluruh retensi bila sudah jadwalnya atau dipaksa.
        2. Jalankan rekonsiliasi terbaru bila sudah jadwalnya atau dipaksa.
        3. Jalankan polling cepat data terbaru.
        4. Gabungkan aliran kandidat dengan urutan deterministik.
        5. Kirim setiap kandidat ke LiveRBTAService.
        6. Flush batch quarantine per siklus sekali, lalu cek breaker.
        7. Flush bucket idle di LiveRBTAService.
        8. Perbarui dan simpan state cursor transport secara atomik bila berhasil.

        Error per record yang deterministik (RawEvidenceConflictError,
        RawEvidenceIntegrityError, RBTAInvariantError, TemporalStateError) serta dokumen
        buruk per hit dari poller (LiveCanonicalizationError yang dikumpulkan di
        ``poller.last_bad_docs``) dikarantina secara durable dalam satu flush batch lalu
        dilewati — siklus tetap berjalan sehingga satu record rusak tidak membutakan ingestion
        live (kebijakan QUARANTINE, bukan berhenti). Hanya pelanggaran pertama untuk sebuah ID
        yang dicatat level error; pengulangannya level debug.

        Kandidat yang ID-nya sudah dikarantina disaring sebelum order buffer (satu snapshot
        quarantine_id_set per siklus, satu query khusus ID, dilaporkan sebagai
        skipped_quarantined), sehingga alert yang terus-menerus rusak tidak pernah di-ingest
        ulang dan tidak pernah menempati buffer. Tanpa penyaringan ini, poll ulang alert yang
        rusak akan mengarantinanya lagi setiap siklus dan breaker di bawah terus trip —
        berhenti permanen dengan cursor beku. ID yang dilewati tidak menambah kegagalan.
        Error sementara tetap dilempar, cursor tidak maju, dan worker melakukan back off.

        Circuit breaker: bila kandidat yang BARU dikarantina melebihi 1% dari yang dikirim
        (atau 100 dalam satu siklus), siklus menyimpan latch ``breaker_tripped`` (trip_id,
        quarantined, submitted, at) ke source state lewat update_live_source_state dan
        melempar RuntimeError tanpa commit cursor — korupsi sistemik menghentikan proses alih-alih
        diserap diam-diam, sementara hasil flush quarantine tetap tersimpan durable. Setiap
        siklus berikutnya error karena latch — tanpa polling, ingest, atau commit — sampai
        dibangun dengan breaker_ack yang cocok, yang membersihkan latch dan melanjutkan siklus.
        ID yang sudah dikarantina tidak pernah sampai ke flush, dan pengulangan yang lolos
        (ID sama dua kali dalam satu siklus) mengembalikan count > 1 dari quarantine_add_many
        sehingga tidak dihitung di pembilang breaker; hanya korupsi yang benar-benar baru yang
        bisa memicunya.

        Parameters
        ----------
        current_time : datetime | None
            Waktu acuan siklus ini (default UTC now).
        force_recent_reconciliation : bool
            Paksa scan rekonsiliasi terbaru.
        force_full_reconciliation : bool
            Paksa sweep menyeluruh seluruh retensi.
        force_reconciliation : bool
            Alias force_recent_reconciliation untuk kompatibilitas.

        Returns
        -------
        LiveCycleResult
            Metrik operasional untuk siklus ini.
        """
        now = current_time or datetime.now(timezone.utc)

        # Breaker-latch: trip sebelumnya menyimpan {"breaker_tripped": {"trip_id", "quarantined",
        # "submitted", "at"}} di source state dan menghentikan setiap siklus — tanpa polling,
        # ingest, atau commit — sampai operator mengonfirmasi dengan trip_id yang cocok
        # (falsy/None = tidak ada latch, siklus lanjut). Konfirmasi yang cocok membersihkan latch.
        latch = self.service.get_live_source_state().get("breaker_tripped")
        if latch:
            trip_id = latch.get("trip_id") if isinstance(latch, dict) else None
            if self.breaker_ack != trip_id:
                raise RuntimeError(
                    f"Quarantine breaker latch active (trip_id={trip_id}); "
                    f"cycle halted without work or commit — acknowledge with "
                    f"breaker_ack='{trip_id}' to resume"
                )
            self.service.update_live_source_state({"breaker_tripped": None})

        # Cek jadwal rekonsiliasi seluruh retensi.
        should_full_recon = force_full_reconciliation
        if not should_full_recon:
            if self.last_full_reconciliation_at is None:
                should_full_recon = True
            elif (now - self.last_full_reconciliation_at) >= self.full_reconciliation_interval:
                should_full_recon = True

        # Dokumen buruk per hit dikuras dari poller setelah setiap jalur poll
        # (poller me-reset last_bad_docs di setiap pemanggilan paginate).
        bad_docs: List[Dict[str, Any]] = []

        def _drain_bad_docs() -> None:
            raw = getattr(self.poller, "last_bad_docs", None)
            if isinstance(raw, list) and raw:
                bad_docs.extend(d for d in raw if isinstance(d, dict))

        full_recon_alerts: List[CanonicalRawAlert] = []
        if should_full_recon:
            full_recon_alerts = self.run_full_reconciliation()
            _drain_bad_docs()

        # Cek jadwal rekonsiliasi terbaru.
        should_recent_recon = force_recent_reconciliation or force_reconciliation
        if not should_recent_recon:
            if self.last_recent_reconciliation_at is None:
                should_recent_recon = True
            elif (now - self.last_recent_reconciliation_at) >= self.recent_reconciliation_interval:
                should_recent_recon = True

        recent_recon_alerts: List[CanonicalRawAlert] = []
        if should_recent_recon:
            recent_recon_alerts = self.run_recent_reconciliation(current_time=now)
            _drain_bad_docs()

        # Poll cepat data terbaru.
        fast_alerts: List[CanonicalRawAlert] = self.run_fast_poll(current_time=now)
        _drain_bad_docs()

        # Gabungkan aliran kandidat dengan dedup di dalam siklus.
        all_candidates: List[CanonicalRawAlert] = []
        seen_in_cycle: Set[str] = set()

        for a in list(full_recon_alerts) + list(recent_recon_alerts) + list(fast_alerts):
            if a.wazuh_alert_id not in seen_in_cycle:
                seen_in_cycle.add(a.wazuh_alert_id)
                all_candidates.append(a)

        # Sort stabil berdasarkan timestamp ASC, wazuh_alert_id ASC.
        all_candidates.sort(key=lambda a: (a.timestamp, a.wazuh_alert_id))

        # Snapshot ID yang sudah dikarantina sekali per siklus (satu query, hanya kolom ID) lalu
        # saring SEBELUM order buffer, sehingga buffer tidak pernah menahan alert yang terus rusak.
        # Tanpa ini, poll ulang akan mengarantinanya setiap siklus dan breaker di bawah terus trip —
        # berhenti permanen dengan cursor beku. ID yang dilewati tidak menambah kegagalan.
        quarantined_ids: Set[str] = self.service.state_manager.quarantine_id_set()
        skipped_quarantined = 0
        if quarantined_ids:
            kept: List[CanonicalRawAlert] = []
            for candidate in all_candidates:
                if candidate.wazuh_alert_id in quarantined_ids:
                    logger.debug(
                        "Skipping already-quarantined alert '%s'; no re-ingest attempted",
                        candidate.wazuh_alert_id,
                    )
                    skipped_quarantined += 1
                else:
                    kept.append(candidate)
            all_candidates = kept

        # Order buffer opsional: tahan kandidat yang tepat waktu, lepaskan hanya yang sudah jatuh
        # tempo menurut watermark / max_hold, ditambah alert terlambat yang langsung diteruskan.
        # Alert yang ditolak karena backpressure langsung di-ingest (terurut) sehingga tidak ada
        # alert valid yang dibuang; kejadiannya terlihat di metrik dan dicatat di log.
        if self.order_buffer is not None:
            # Duplikat yang sudah seen melewati buffer langsung ke ingest (cek konflik tetap berlaku)
            # supaya poll ulang dari rekonsiliasi tidak mengotori metrik alert terlambat.
            # Keanggotaan is_seen di-snapshot sekali per kandidat per siklus — partisi dan loop ingest
            # berbagi cache ini alih-alih dua kali query ke SQLite. (Service tidak punya bulk loader;
            # memuat seluruh tabel seen berarti O(tabel), jadi memoization per siklus adalah snapshot
            # yang murah dan benar.)
            seen_cache: Dict[str, bool] = {}

            def _cached_is_seen(alert_id: str) -> bool:
                if alert_id not in seen_cache:
                    seen_cache[alert_id] = self.service.is_seen(alert_id)
                return seen_cache[alert_id]

            unseen, already_seen = partition_unseen(all_candidates, _cached_is_seen)
            buffered_releases = self.order_buffer.add(unseen, now=now)
            refused = self.order_buffer.pop_refused()
            if refused:
                logger.warning(
                    "Order buffer backpressure: %d candidate(s) refused "
                    "(backpressure_count=%d); ingesting directly to avoid loss",
                    len(refused),
                    self.order_buffer.status()["backpressure_count"],
                )
                refused.sort(key=lambda a: (a.timestamp, a.wazuh_alert_id))
            all_candidates = [r.alert for r in buffered_releases] + refused + already_seen

        # Ingest kandidat lewat LiveRBTAService.
        new_ids_count = 0
        duplicate_noops = 0
        failures = 0
        total_scored: List[ScoredMetaAlert] = []
        ingested_event_times: List[datetime] = []
        newly_ingested: List[CanonicalRawAlert] = []
        future_cutoff = now + _FUTURE_EVENT_SKEW

        # Entri quarantine dikumpulkan per siklus dan di-flush sekali (satu transaksi) sebelum
        # commit cursor. Pesannya disimpan juga untuk log error pelanggaran pertama.
        pending_quarantine: List[Dict[str, Any]] = []
        pending_messages: List[str] = []

        use_seen_cache = self.order_buffer is not None

        for candidate in all_candidates:
            if use_seen_cache and candidate.wazuh_alert_id in seen_cache:
                is_already_seen = seen_cache[candidate.wazuh_alert_id]
            else:
                is_already_seen = self.service.is_seen(candidate.wazuh_alert_id)
            try:
                scored_list = self.service.ingest_alert(candidate)
                total_scored.extend(scored_list)
                if is_already_seen:
                    duplicate_noops += 1
                else:
                    new_ids_count += 1
                    if use_seen_cache:
                        seen_cache[candidate.wazuh_alert_id] = True
                # Hanya ID yang baru di-ingest yang diarsipkan, agar arsip bebas duplikat untuk replay nanti.
                if not is_already_seen:
                    newly_ingested.append(candidate)
                # Hanya event time yang berhasil di-ingest dan bukan dari masa depan yang boleh
                # memajukan newest_ingested_event_time.
                if candidate.timestamp.tzinfo is None or candidate.timestamp <= future_cutoff:
                    ingested_event_times.append(candidate.timestamp)
            except _QUARANTINE_ERRORS as exc:
                meta = dict(candidate.metadata)
                pending_quarantine.append({
                    "wazuh_alert_id": candidate.wazuh_alert_id,
                    "source_index": str(meta.get("source_index", "") or ""),
                    "source_document_id": str(meta.get("source_document_id", "") or ""),
                    "error_type": type(exc).__name__,
                })
                pending_messages.append(str(exc))
                failures += 1
                continue
            except Exception as exc:
                logger.error("Failed to ingest alert '%s': %s", candidate.wazuh_alert_id, exc)
                failures += 1
                raise

        # Arsip JSONL mentah (best effort) untuk alert yang baru di-ingest di siklus ini
        # (diurutkan dan dirotasi harian di dalam append_alerts). append_alerts tidak pernah error;
        # guard tambahan ini menjaga siklus live tetap jalan apa pun yang terjadi di jalur arsip.
        if self.live_archive_enabled and newly_ingested:
            try:
                from src.runtime.live_archive import append_alerts
                append_alerts(newly_ingested, self.live_archive_dir)
            except Exception as exc:
                logger.warning("Live archive batch failed: %s", exc)

        # Setiap dokumen buruk per hit dikarantina, lalu siklus berlanjut. Dokumen tanpa identitas
        # diberi kunci hash isi dari {index, doc_id} SAJA — page_pos (yang ada di teks error) tidak
        # ikut, sehingga dokumen identik yang di-poll ulang mendapat kunci stabil yang sama antar siklus
        # dan pengulangannya dilewati sebagai sudah dikarantina, bukan dikarantina ulang dengan kunci
        # posisi baru setiap siklus.
        for bad in bad_docs:
            doc_id = bad.get("doc_id")
            if doc_id:
                quarantine_key = str(doc_id)
            else:
                digest = hashlib.sha256(
                    json.dumps(
                        {"index": bad.get("index"), "doc_id": bad.get("doc_id")},
                        sort_keys=True,
                        default=str,
                    ).encode("utf-8")
                ).hexdigest()[:12]
                quarantine_key = f"unidentified:{digest}"
            if quarantine_key in quarantined_ids:
                logger.debug(
                    "Skipping already-quarantined bad document '%s'; no re-ingest attempted",
                    quarantine_key,
                )
                continue
            pending_quarantine.append({
                "wazuh_alert_id": quarantine_key,
                "source_index": str(bad.get("index") or ""),
                "source_document_id": str(doc_id or ""),
                "error_type": "LiveCanonicalizationError",
            })
            pending_messages.append(str(bad.get("error") or ""))
            failures += 1

        # Satu flush quarantine per batch (sebelum commit cursor) + breaker.
        quarantined = 0
        if pending_quarantine:
            counts = self.service.state_manager.quarantine_add_many(pending_quarantine)
            new_quarantined = 0
            for entry, message, count in zip(pending_quarantine, pending_messages, counts):
                if count <= 1:
                    new_quarantined += 1
                    logger.error(
                        "Quarantining alert '%s' (%s): %s",
                        entry["wazuh_alert_id"], entry["error_type"], message,
                    )
                else:
                    logger.debug(
                        "Quarantining repeat alert '%s' (%s, offense #%d)",
                        entry["wazuh_alert_id"], entry["error_type"], count,
                    )
            quarantined = len(pending_quarantine)

            # Breaker hanya menghitung quarantine BARU (count == 1).
            submitted = len(all_candidates)
            fraction = (new_quarantined / submitted) if submitted else 0.0
            if new_quarantined > _QUARANTINE_BREAKER_ABSOLUTE or (
                submitted and fraction > _QUARANTINE_BREAKER_FRACTION
            ):
                trip_id = f"qb-{now.strftime('%Y%m%d%H%M%S')}-{new_quarantined}"
                # Latch dulu SEBELUM error: hasil flush quarantine di atas tetap tersimpan durable, cursor
                # TIDAK di-commit, dan setiap siklus berikutnya berhenti karena latch sampai operator
                # mengonfirmasi dengan trip_id ini.
                self.service.update_live_source_state({
                    "breaker_tripped": {
                        "trip_id": trip_id,
                        "quarantined": new_quarantined,
                        "submitted": submitted,
                        "at": now.isoformat(),
                    },
                })
                raise RuntimeError(
                    f"Quarantine circuit breaker tripped: {new_quarantined}/{submitted} "
                    f"new candidates quarantined in one cycle (fraction={fraction:.2%}, "
                    f"threshold=1% or 100); halting without committing the cursor — "
                    f"trip_id={trip_id}; inspect quarantined_alerts and acknowledge "
                    f"with breaker_ack='{trip_id}' before resuming"
                )

        # Flush bucket idle.
        flushed_scored = self.service.check_idle_flush(now)
        total_scored.extend(flushed_scored)

        # Commit state transport secara atomik bila siklus selesai dengan sukses.
        self.last_fast_poll_at = now
        if should_recent_recon:
            self.last_recent_reconciliation_at = now
        if should_full_recon:
            self.last_full_reconciliation_at = now

        if self.recent_poll_cursor is None or now > self.recent_poll_cursor:
            self.recent_poll_cursor = now

        # Maksimum hanya dari kandidat yang berhasil di-ingest dan bukan dari masa depan;
        # timestamp yang dikarantina/rusak atau dari masa depan tidak pernah menggeser telemetri lag.
        # None eksplisit bila tidak ada yang memenuhi (tidak pernah basi).
        newest_event = max(ingested_event_times, default=None)
        self.service.update_live_source_state({
            "recent_poll_cursor": self.recent_poll_cursor.isoformat() if self.recent_poll_cursor else None,
            "newest_ingested_event_time": newest_event.isoformat() if newest_event else None,
            "last_fast_poll_at": self.last_fast_poll_at.isoformat() if self.last_fast_poll_at else None,
            "last_recent_reconciliation_at": (
                self.last_recent_reconciliation_at.isoformat()
                if self.last_recent_reconciliation_at
                else None
            ),
            "last_reconciliation_at": (
                self.last_recent_reconciliation_at.isoformat()
                if self.last_recent_reconciliation_at
                else None
            ),
            "last_full_reconciliation_at": (
                self.last_full_reconciliation_at.isoformat()
                if self.last_full_reconciliation_at
                else None
            ),
            "recent_reconciliation_days": self.recent_reconciliation_days,
        })

        return LiveCycleResult(
            fast_candidates=len(fast_alerts),
            recent_reconciliation_candidates=len(recent_recon_alerts),
            full_reconciliation_candidates=len(full_recon_alerts),
            submitted_candidates=len(all_candidates),
            duplicate_noops=duplicate_noops,
            processed_new_ids=new_ids_count,
            failures=failures,
            new_scored_meta_alerts=len(total_scored),
            quarantined=quarantined,
            skipped_quarantined=skipped_quarantined,
        )
