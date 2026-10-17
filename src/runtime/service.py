"""Service runtime RBTA live yang stateful: mengoordinasikan agregasi, scoring, dan outbox."""

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import logging
from functools import wraps
from threading import RLock
from typing import Any, Dict, List, Optional

from src.config.research import DEFAULT_BASE_DELTA_T
from src.contracts.meta_alert import MetaAlert
from src.contracts.raw_alert import CanonicalRawAlert
from src.contracts.scored_meta_alert import ScoredMetaAlert
from src.model.scoring_pipeline import ScoringPipeline
from src.rbta.engine import RBTAEngine
from src.runtime.durable_state import DurableStateManager

logger = logging.getLogger(__name__)


def _serialized(method):
    """Serialkan satu mutasi service secara utuh, termasuk commit durable-nya."""
    @wraps(method)
    def wrapped(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    return wrapped


def _serialize_meta_alert(meta: MetaAlert) -> Dict[str, Any]:
    """Ubah MetaAlert menjadi dict yang bisa diserialisasi ke JSON."""
    return {
        "meta_id": meta.meta_id,
        "agent_id": meta.agent_id,
        "agent_name": meta.agent_name,
        "rule_group_primary": meta.rule_group_primary,
        "start_time": meta.start_time.isoformat() if meta.start_time else None,
        "end_time": meta.end_time.isoformat() if meta.end_time else None,
        "alert_count": meta.alert_count,
        "max_severity": meta.max_severity,
        "rule_id_distribution": dict(meta.rule_id_distribution),
        "severity_distribution": {str(k): v for k, v in meta.severity_distribution.items()},
        "agent_criticality": meta.agent_criticality,
        "wazuh_alert_ids": list(meta.wazuh_alert_ids),
        "mitre_tactics_unique": list(meta.mitre_tactics_unique),
        "critical_mitre_present": meta.critical_mitre_present,
        "metadata": dict(meta.metadata),
    }


def _parse_meta_alert(item: Any) -> Optional[MetaAlert]:
    """Parse dict atau objek MetaAlert dengan aman."""
    if isinstance(item, MetaAlert):
        return item
    if isinstance(item, dict) and "meta_id" in item:
        try:
            return MetaAlert(
                meta_id=item["meta_id"],
                agent_id=item.get("agent_id", "001"),
                agent_name=item.get("agent_name", "unknown"),
                rule_group_primary=item.get("rule_group_primary", "unknown"),
                start_time=datetime.fromisoformat(item["start_time"]) if item.get("start_time") else None,
                end_time=datetime.fromisoformat(item["end_time"]) if item.get("end_time") else None,
                alert_count=item.get("alert_count", 1),
                max_severity=item.get("max_severity", 3),
                rule_id_distribution=item.get("rule_id_distribution", {}),
                severity_distribution={int(k): v for k, v in item.get("severity_distribution", {}).items()},
                agent_criticality=item.get("agent_criticality", 1),
                wazuh_alert_ids=tuple(item.get("wazuh_alert_ids", ())),
                mitre_tactics_unique=tuple(item.get("mitre_tactics_unique", ())),
                critical_mitre_present=item.get("critical_mitre_present", False),
                metadata=item.get("metadata", {}),
            )
        except Exception as exc:
            logger.warning("Error parsing MetaAlert: %s", exc)
    return None


def _serialize_scored_alert(scored: ScoredMetaAlert) -> Dict[str, Any]:
    """Ubah ScoredMetaAlert menjadi dict yang bisa diserialisasi ke JSON."""
    return {
        "meta_id": scored.meta_id,
        "agent_id": scored.agent_id,
        "agent_name": scored.agent_name,
        "rule_group_primary": scored.rule_group_primary,
        "start_time": scored.start_time.isoformat(),
        "end_time": scored.end_time.isoformat(),
        "alert_count": scored.alert_count,
        "max_severity": scored.max_severity,
        "mitre_tactics": list(scored.mitre_tactics),
        "seven_features": dict(scored.seven_features),
        "raw_model_score": scored.raw_model_score,
        "anomaly_score": scored.anomaly_score,
        "threshold_used": scored.threshold_used,
        "decision": scored.decision,
        "action": scored.action,
        "escalate": scored.escalate,
        "model_version": scored.model_version,
        "feature_schema_version": scored.feature_schema_version,
        "score_calibration_version": scored.score_calibration_version,
        "source_alert_ids": list(scored.source_alert_ids),
        "metadata": dict(scored.metadata),
    }


class LiveRBTAService:
    """Service operasional live yang stateful: mengelola RBTA, scoring online, dan antrean outbox.

    Parameters
    ----------
    scoring_pipeline : ScoringPipeline
        Scoring pipeline model yang sudah dimuat.
    state_manager : DurableStateManager | None
        Pengelola state durable untuk pemulihan crash.
    base_delta_t : timedelta
        Window waktu agregasi eksperimen.
    adaptive : bool
        Aktifkan adaptasi EMA per agent setelah warmup 100 event.
    """

    RECENT_HISTORY_LIMIT = 1000

    def __init__(
        self,
        scoring_pipeline: ScoringPipeline,
        state_manager: Optional[DurableStateManager] = None,
        base_delta_t: timedelta = DEFAULT_BASE_DELTA_T,
        adaptive: bool = True,
        raw_evidence_store: Optional[Any] = None,
        source_mode: str = 'LIVE',
        escalation_sink: Optional[Any] = None,
        run_id: Optional[str] = None,
        auto_persist: bool = True,
    ) -> None:
        self.scoring_pipeline: ScoringPipeline = scoring_pipeline
        self.state_manager: DurableStateManager = state_manager or DurableStateManager()
        self.base_delta_t: timedelta = base_delta_t
        self.adaptive: bool = adaptive
        self.raw_evidence_store = raw_evidence_store
        self.source_mode = source_mode
        self.escalation_sink = escalation_sink
        self.run_id = run_id
        self.auto_persist = auto_persist
        self._lock = RLock()

        self.engine: RBTAEngine = RBTAEngine(base_delta_t=self.base_delta_t, adaptive=self.adaptive)
        self.pending_scoring: List[MetaAlert] = []
        self.outbox: List[ScoredMetaAlert] = []
        self.finalized_history: List[ScoredMetaAlert] = []
        self.source_checkpoint: Dict[str, Any] = {}
        self._last_persisted_history_idx = 0
        # Wall-clock UTC saat engine memfinalkan MetaAlert (meta_id -> ISO); ditulis ke kolom
        # finalized_history.finalized_at saat checkpoint, lalu dibuang dari memori.
        self._finalized_at: Dict[int, str] = {}

        # Pulihkan dari state durable saat startup.
        self._restore_from_disk()

    def _parse_scored_alert(self, item: Any) -> Optional[ScoredMetaAlert]:
        if isinstance(item, ScoredMetaAlert):
            return item
        if isinstance(item, dict) and "meta_id" in item and "anomaly_score" in item:
            try:
                return ScoredMetaAlert(
                    meta_id=item["meta_id"],
                    agent_id=item.get("agent_id", "001"),
                    agent_name=item.get("agent_name", "unknown"),
                    rule_group_primary=item.get("rule_group_primary", "unknown"),
                    start_time=datetime.fromisoformat(item["start_time"]) if "start_time" in item else datetime.now(timezone.utc),
                    end_time=datetime.fromisoformat(item["end_time"]) if "end_time" in item else datetime.now(timezone.utc),
                    alert_count=item.get("alert_count", 1),
                    max_severity=item.get("max_severity", 3),
                    mitre_tactics=tuple(item.get("mitre_tactics", ())),
                    seven_features=item.get("seven_features", {}),
                    raw_model_score=item.get("raw_model_score", 0.0),
                    anomaly_score=item.get("anomaly_score", 0.0),
                    threshold_used=item.get("threshold_used", 0.0),
                    decision=item.get("decision", "NOISE"),
                    action=item.get("action", "SUPPRESS"),
                    escalate=item.get("escalate", False),
                    model_version=item.get("model_version", "v1"),
                    feature_schema_version=item.get("feature_schema_version", "1.0"),
                    score_calibration_version=item.get("score_calibration_version", "minmax-v1"),
                    source_alert_ids=tuple(item.get("source_alert_ids", ())),
                    metadata=item.get("metadata", {}),
                )
            except Exception as exc:
                logger.warning("Error parsing scored alert: %s", exc)
        return None

    def _enqueue_finalized(self, metas: List[MetaAlert]) -> None:
        """Antrekan MetaAlert final untuk scoring dan catat waktu finalisasinya (latensi T7)."""
        now = datetime.now(timezone.utc).isoformat()
        for meta in metas:
            self._finalized_at.setdefault(meta.meta_id, now)
        self.pending_scoring.extend(metas)

    def _restore_from_disk(self) -> None:
        """Coba pulihkan state engine, pending scoring, dan outbox dari disk."""
        restored = self.state_manager.restore_state(self.engine, hydrate_seen_ids=False)
        self.source_checkpoint = restored.get("source_checkpoint", {})
        raw_pending = restored.get("pending_scoring", [])
        raw_outbox = restored.get("outbox", [])
        raw_history = restored.get("finalized_history", [])

        for item in raw_pending:
            meta = _parse_meta_alert(item)
            if meta:
                self.pending_scoring.append(meta)

        for item in raw_outbox:
            meta = self._parse_scored_alert(item)
            if meta:
                self.outbox.append(meta)

        for item in raw_history:
            meta = self._parse_scored_alert(item)
            if meta:
                self.finalized_history.append(meta)
                
        self._last_persisted_history_idx = len(self.finalized_history)

        if self.scoring_pipeline and self.pending_scoring:
            self._drain_pending_scoring()

    @_serialized
    def _persist_to_disk(self) -> None:
        """Simpan state saat ini, pending scoring, dan outbox ke disk."""
        if self.raw_evidence_store is not None and hasattr(self.raw_evidence_store, "flush"):
            self.raw_evidence_store.flush()
        pending_payload = [_serialize_meta_alert(item) for item in self.pending_scoring]
        outbox_payload = [_serialize_scored_alert(item) for item in self.outbox]
        
        new_items = self.finalized_history[self._last_persisted_history_idx:]
        history_payload = [_serialize_scored_alert(item) for item in new_items]
        
        self.state_manager.save_state(
            engine=self.engine,
            outbox=outbox_payload,
            source_checkpoint=self.source_checkpoint,
            new_finalized_history=history_payload,
            pending_scoring=pending_payload,
            finalized_at=self._finalized_at,
        )
        for item in new_items:
            self._finalized_at.pop(item.meta_id, None)
        # SQLite adalah index duplikat acuan. Di memori cukup disimpan hot set terbatas
        # untuk request berulang yang cepat di proses ini.
        if len(self.engine._seen_alert_ids) > 10_000:
            self.engine._seen_alert_ids = set(list(self.engine._seen_alert_ids)[-10_000:])
        if len(self.finalized_history) > self.RECENT_HISTORY_LIMIT:
            self.finalized_history = self.finalized_history[-self.RECENT_HISTORY_LIMIT:]
        self._last_persisted_history_idx = len(self.finalized_history)

    @_serialized
    def checkpoint(self) -> None:
        """Simpan state durable saat ini ke disk secara eksplisit."""
        self._persist_to_disk()

    @_serialized
    def _drain_pending_scoring(self, auto_persist: Optional[bool] = None) -> List[ScoredMetaAlert]:
        """Skor meta-alert yang tertunda lalu commit dengan aman ke outbox dan history.

        Diserialkan dengan lock service (RLock reentrant, jadi pemanggilan bersarang dari
        ingest/flush/shutdown aman) agar pemanggilan langsung dari luar tidak balapan dengan
        mutasi ingest/flush yang berjalan bersamaan.
        """
        should_persist = self.auto_persist if auto_persist is None else auto_persist
        new_scored: List[ScoredMetaAlert] = []
        while self.pending_scoring:
            meta = self.pending_scoring[0]
            scored = self.scoring_pipeline.score_single(meta)
            if scored.action == "ESCALATE":
                self.outbox.append(scored)
            self.finalized_history.append(scored)
            if self.escalation_sink is not None and scored.action == "ESCALATE":
                try:
                    self.escalation_sink.emit(scored, self.run_id or "live")
                except Exception as exc:
                    logger.error("Failed to emit escalation to sink: %s", exc)
            new_scored.append(scored)
            self.pending_scoring.pop(0)
            if should_persist:
                self._persist_to_disk()
        return new_scored

    @_serialized
    def ingest_alert(
        self,
        alert: CanonicalRawAlert,
        auto_persist: Optional[bool] = None,
        original_payload: Optional[Dict[str, Any]] = None,
    ) -> List[ScoredMetaAlert]:
        """Proses raw alert kanonis yang masuk lewat RBTA dan scoring.

        Parameters
        ----------
        alert : CanonicalRawAlert
            Alert yang masuk, sudah dinormalisasi.
        auto_persist : bool | None
            Apakah alert ini memicu flush file state secara sinkron.

        Returns
        -------
        List[ScoredMetaAlert]
            Meta-alert yang baru difinalkan dan diskor pada langkah ini.
        """
        should_persist = self.auto_persist if auto_persist is None else auto_persist
        if self.raw_evidence_store is not None:
            # Payload asli tidak tersedia di sini, jadi diteruskan None.
            # CATATAN: skip_conflict_check adalah no-op lama yang dipertahankan untuk kompatibilitas
            # API; store selalu menjalankan deteksi konflik kanonis, termasuk untuk mode sumber REPLAY.
            self.raw_evidence_store.store(
                alert,
                original_payload=original_payload,
                source_mode=self.source_mode,
                skip_conflict_check=(self.source_mode == "REPLAY")
            )
            if should_persist and hasattr(self.raw_evidence_store, "flush"):
                self.raw_evidence_store.flush()

        if self.state_manager.has_seen_alert_id(alert.wazuh_alert_id):
            return []

        finalized_metas = self.engine.process(alert)
        if finalized_metas:
            self._enqueue_finalized(finalized_metas)

        if should_persist:
            self._persist_to_disk()
        return self._drain_pending_scoring(auto_persist=should_persist)

    @_serialized
    def check_idle_flush(self, current_event_time: datetime, auto_persist: Optional[bool] = None) -> List[ScoredMetaAlert]:
        """Flush dan skor bucket aktif yang lama idle-nya benar-benar melebihi delta_t.

        Parameters
        ----------
        current_event_time : datetime
            Timestamp event acuan.
        auto_persist : bool | None
            Apakah memicu flush file state secara sinkron.

        Returns
        -------
        List[ScoredMetaAlert]
            Meta-alert yang baru difinalkan dan diskor.
        """
        should_persist = self.auto_persist if auto_persist is None else auto_persist
        finalized_metas = self.engine.flush_idle(current_event_time)
        if finalized_metas:
            self._enqueue_finalized(finalized_metas)
            if should_persist:
                self._persist_to_disk()

        return self._drain_pending_scoring(auto_persist=should_persist)

    def get_outbox(self) -> List[ScoredMetaAlert]:
        """Ambil meta-alert terskor di outbox yang belum dikonfirmasi."""
        return list(self.outbox)

    @_serialized
    def acknowledge_outbox(self, meta_id: int) -> None:
        """Konfirmasi dan hapus satu meta-alert terskor dari outbox."""
        self.outbox = [item for item in self.outbox if item.meta_id != meta_id]
        self._persist_to_disk()

    @_serialized
    def commit_outbox(self, meta_ids: List[int]) -> int:
        """Konfirmasi dan hapus beberapa meta-alert terskor dari outbox."""
        initial = len(self.outbox)
        self.outbox = [item for item in self.outbox if item.meta_id not in meta_ids]
        self._persist_to_disk()
        return initial - len(self.outbox)

    def get_history(self) -> List[ScoredMetaAlert]:
        return list(self.finalized_history)

    def query_history(self, **filters: Any) -> tuple[List[ScoredMetaAlert], int]:
        raw_items, total = self.state_manager.query_finalized(**filters)
        items = [parsed for raw in raw_items if (parsed := self._parse_scored_alert(raw)) is not None]
        return items, total

    def get_meta_detail(self, meta_id: int) -> Optional[ScoredMetaAlert]:
        for item in self.finalized_history:
            if item.meta_id == meta_id:
                return item
        raw = self.state_manager.get_finalized(meta_id)
        return self._parse_scored_alert(raw) if raw else None

    def is_seen(self, wazuh_alert_id: str) -> bool:
        """Cek apakah ID alert sudah di-commit di RBTAEngine."""
        in_memory = self.engine.has_seen_alert(wazuh_alert_id) if hasattr(self.engine, "has_seen_alert") else (wazuh_alert_id in self.engine._seen_alert_ids)
        return in_memory or self.state_manager.has_seen_alert_id(wazuh_alert_id)

    @_serialized
    def drain_and_score(self) -> List[ScoredMetaAlert]:
        """Kuras semua bucket engine yang sedang aktif, skor, lalu simpan."""
        drained_metas = self.engine.drain()
        if drained_metas:
            self._enqueue_finalized(drained_metas)
            self._persist_to_disk()
            return self._drain_pending_scoring()
        return []

    def get_live_source_state(self) -> Dict[str, Any]:
        """Ambil salinan state transport live source yang durable."""
        return dict(self.source_checkpoint)

    @_serialized
    def update_live_source_state(self, state: Dict[str, Any]) -> None:
        """Perbarui dan simpan state transport live source secara atomik."""
        self.source_checkpoint.update(state)
        self._persist_to_disk()

    @_serialized
    def shutdown(self, drain: bool = False) -> List[ScoredMetaAlert]:
        """Shutdown terkendali, opsional dengan menguras bucket aktif.

        Parameters
        ----------
        drain : bool
            Apakah semua bucket aktif difinalkan dan di-flush saat shutdown.

        Returns
        -------
        List[ScoredMetaAlert]
            Meta-alert final yang di-flush selama drain.
        """
        if drain:
            drained_metas = self.engine.drain()
            if drained_metas:
                self._enqueue_finalized(drained_metas)

        self._persist_to_disk()
        return self._drain_pending_scoring()
