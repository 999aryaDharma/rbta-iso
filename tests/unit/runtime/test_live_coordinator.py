"""Unit test LiveIngestionCoordinator (fast poll + rekonsiliasi terbaru + sweep seluruh retensi)."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from src.contracts.raw_alert import CanonicalRawAlert
from src.contracts.scored_meta_alert import ScoredMetaAlert
from src.model.scoring_pipeline import ScoringPipeline, train_reference_pipeline
from src.runners.batch_runner import BatchResearchRunner
from src.runtime.durable_state import DurableStateManager
from src.runtime.live_coordinator import LiveCycleResult, LiveIngestionCoordinator
from src.runtime.live_source import LiveCanonicalizationError, WazuhIndexerLivePoller
from src.runtime.service import LiveRBTAService


def make_raw_alert(
    idx: int,
    ts: datetime,
    group: str = "pam",
    level: int = 3,
    crit: int = 1,
) -> CanonicalRawAlert:
    return CanonicalRawAlert(
        wazuh_alert_id=f"alert_{idx}",
        timestamp=ts,
        agent_id="001",
        agent_name="soc-1",
        rule_group_primary=group,
        rule_level=level,
        rule_id=f"550{idx % 5}",
        mitre_tactics=(),
        srcip=None,
        agent_criticality=crit,
    )


def create_test_service(tmp_path: Path) -> LiveRBTAService:
    base_t = datetime(2026, 8, 28, 8, 0, 0, tzinfo=timezone.utc)
    sample_alerts = [
        make_raw_alert(i, base_t + timedelta(minutes=i * 20), level=(i % 12) + 1)
        for i in range(30)
    ]
    batch_res = BatchResearchRunner(base_delta_t=timedelta(minutes=15), adaptive=False).run(sample_alerts)
    bundle = train_reference_pipeline(batch_res.meta_alerts, random_state=42, model_version="coord-test-v1")
    scoring_pipe = ScoringPipeline(bundle)

    state_mgr = DurableStateManager(tmp_path / "coordinator_service_state.json")
    return LiveRBTAService(
        scoring_pipeline=scoring_pipe,
        state_manager=state_mgr,
        base_delta_t=timedelta(minutes=15),
        adaptive=False,
    )


def test_coordinator_fast_poll_and_reconciliation_cycle(tmp_path: Path):
    """Coordinator menjalankan rekonsiliasi dan fast poll, men-dedup, lalu meng-ingest kandidat."""
    service = create_test_service(tmp_path)
    poller = MagicMock(spec=WazuhIndexerLivePoller)

    t_now = datetime(2026, 8, 28, 10, 30, 0, tzinfo=timezone.utc)
    a1 = make_raw_alert(1, t_now - timedelta(minutes=2))
    a2 = make_raw_alert(2, t_now - timedelta(minutes=1))

    poller.poll_recent.return_value = [a1, a2]
    poller.poll_reconciliation.return_value = [a1]
    poller.poll_full_reconciliation.return_value = []

    coord = LiveIngestionCoordinator(
        service=service,
        poller=poller,
        recent_reconciliation_interval=timedelta(minutes=5),
        full_reconciliation_interval=timedelta(hours=1),
    )

    result = coord.run_cycle(current_time=t_now, force_recent_reconciliation=True)

    assert result.fast_candidates == 2
    assert result.recent_reconciliation_candidates == 1
    assert result.submitted_candidates == 2
    assert result.processed_new_ids == 2
    assert result.duplicate_noops == 0
    assert result.failures == 0

    assert service.is_seen("alert_1")
    assert service.is_seen("alert_2")


def test_coordinator_full_retention_reconciliation_recovers_old_alert(tmp_path: Path):
    """Sweep seluruh retensi menemukan alert dari beberapa hari sebelumnya (20 Agt saat hari ini 29 Agt)."""
    service = create_test_service(tmp_path)
    poller = MagicMock(spec=WazuhIndexerLivePoller)

    t_now = datetime(2026, 8, 29, 10, 0, 0, tzinfo=timezone.utc)
    a_recent = make_raw_alert(99, t_now - timedelta(minutes=2))
    a_old_retained = make_raw_alert(10, datetime(2026, 8, 20, 10, 0, 0, tzinfo=timezone.utc))

    poller.poll_recent.return_value = [a_recent]
    poller.poll_reconciliation.return_value = [a_recent]
    poller.poll_full_reconciliation.return_value = [a_old_retained, a_recent]

    coord = LiveIngestionCoordinator(service=service, poller=poller)

    result = coord.run_cycle(current_time=t_now, force_full_reconciliation=True)

    assert service.is_seen("alert_99")
    assert service.is_seen("alert_10")
    assert result.processed_new_ids == 2
    assert result.full_reconciliation_candidates == 2


def _stub_service(tmp_path: Path):
    """Stub service yang murah: DurableStateManager asli, jalur ingest di-mock."""
    service = MagicMock()
    service.state_manager = DurableStateManager(tmp_path / "stub_state.json")
    service.is_seen.return_value = False
    service.check_idle_flush.return_value = []
    service.get_live_source_state.return_value = {}
    service.update_live_source_state.side_effect = lambda s: None
    return service


def _scale_alerts(n: int, t_now, step_s: int = 20, start: int = 0):
    return [
        make_raw_alert(start + i, t_now - timedelta(seconds=(n - i) * step_s))
        for i in range(n)
    ]


def test_coordinator_bad_docs_quarantined_per_hit_and_cycle_commits(tmp_path: Path):
    """Dokumen buruk per hit yang dikuras dari poller.last_bad_docs dikarantina
    (error_type LiveCanonicalizationError); alert valid tetap di-ingest; cursor di-commit.
    """
    from datetime import timezone as _tz

    service = _stub_service(tmp_path)
    service.ingest_alert.side_effect = lambda a: []
    poller = MagicMock()
    t_now = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    valid = _scale_alerts(150, t_now)
    bad = {"index": "wazuh-alerts-4.x-2026.08.28", "doc_id": "doc_bad", "error": "boom"}

    def _full(*a, **k):
        poller.last_bad_docs = []
        return []

    def _recent(*a, **k):
        poller.last_bad_docs = []
        return []

    def _fast(*a, **k):
        poller.last_bad_docs = [bad]
        return valid

    poller.poll_full_reconciliation.side_effect = _full
    poller.poll_reconciliation.side_effect = _recent
    poller.poll_recent.side_effect = _fast
    poller.last_bad_docs = []

    coord = LiveIngestionCoordinator(service=service, poller=poller)
    result = coord.run_cycle(current_time=t_now)

    assert result.submitted_candidates == 150
    assert result.quarantined == 1
    assert result.processed_new_ids == 150
    rows = service.state_manager.quarantine_list()
    assert len(rows) == 1
    assert rows[0]["wazuh_alert_id"] == "doc_bad"
    assert rows[0]["error_type"] == "LiveCanonicalizationError"
    assert service.update_live_source_state.called  # cursor di-commit saat berhasil


def test_coordinator_quarantines_rbta_and_temporal_errors_and_continues(tmp_path: Path):
    """RBTAInvariantError + TemporalStateError adalah quarantine deterministik, bukan halt sementara;
    engine.process atomik saat gagal (diverifikasi di bawah).
    """
    from src.rbta.engine import RBTAInvariantError
    from src.rbta.temporal_state import TemporalStateError

    service = _stub_service(tmp_path)

    def _ingest(alert):
        if alert.wazuh_alert_id == "alert_5":
            raise RBTAInvariantError("contradictory criticality")
        if alert.wazuh_alert_id == "alert_7":
            raise TemporalStateError("terminal invalid")
        return []

    service.ingest_alert.side_effect = _ingest
    poller = MagicMock()
    t_now = datetime(2026, 8, 28, 10, 30, 0, tzinfo=timezone.utc)
    poller.poll_recent.return_value = _scale_alerts(200, t_now)
    poller.poll_reconciliation.return_value = []
    poller.poll_full_reconciliation.return_value = []
    poller.last_bad_docs = []

    coord = LiveIngestionCoordinator(service=service, poller=poller)
    result = coord.run_cycle(current_time=t_now)

    assert result.failures == 2
    assert result.quarantined == 2
    assert result.processed_new_ids == 198
    by_id = {r["wazuh_alert_id"]: r["error_type"] for r in service.state_manager.quarantine_list()}
    assert by_id == {"alert_5": "RBTAInvariantError", "alert_7": "TemporalStateError"}
    assert service.update_live_source_state.called


def test_engine_process_invariant_error_is_failure_atomic():
    """Bukti: kritikalitas yang bertentangan tidak mengubah state engine sama sekali."""
    from src.rbta.engine import RBTAEngine, RBTAInvariantError

    engine = RBTAEngine(base_delta_t=timedelta(minutes=15), adaptive=False)
    t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    engine.process(make_raw_alert(1, t))
    counter_before = engine._meta_id_counter

    bad = make_raw_alert(2, t + timedelta(minutes=1), crit=4)
    with pytest.raises(RBTAInvariantError):
        engine.process(bad)

    assert "alert_2" not in engine._seen_alert_ids
    assert "alert_2" not in engine._new_seen_alert_ids
    assert engine._meta_id_counter == counter_before
    assert engine._active_buckets[("001", "pam")].alert_count == 1


def test_engine_process_temporal_error_is_failure_atomic():
    """Bukti: state temporal terminal-invalid tidak mengubah state commit sama sekali."""
    from src.rbta.engine import RBTAEngine
    from src.rbta.temporal_state import TemporalStateError

    engine = RBTAEngine()  # adaptive: 100 gap identik -> baseline 0 -> terminal invalid
    t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    for i in range(99):
        engine.process(make_raw_alert(i, t))
    counter_before = engine._meta_id_counter

    with pytest.raises(TemporalStateError):
        engine.process(make_raw_alert(99, t))

    assert "alert_99" not in engine._seen_alert_ids
    assert engine._meta_id_counter == counter_before


def test_coordinator_quarantine_breaker_trips_on_fraction(tmp_path: Path):
    """Fraksi quarantine >1% menghentikan siklus (cursor tidak di-commit)."""
    from src.runtime.raw_evidence import RawEvidenceConflictError

    service = _stub_service(tmp_path)
    service.ingest_alert.side_effect = RawEvidenceConflictError("systemic poison")
    poller = MagicMock()
    t_now = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    poller.poll_recent.return_value = _scale_alerts(5, t_now)
    poller.poll_reconciliation.return_value = []
    poller.poll_full_reconciliation.return_value = []
    poller.last_bad_docs = []

    coord = LiveIngestionCoordinator(service=service, poller=poller)
    with pytest.raises(RuntimeError, match="[Qq]uarantine"):
        coord.run_cycle(current_time=t_now)
    # Latch: breaker_tripped tersimpan, key cursor transport TIDAK di-commit.
    assert service.update_live_source_state.called
    payload = service.update_live_source_state.call_args.args[0]
    assert payload["breaker_tripped"]["quarantined"] == 5
    assert payload["breaker_tripped"]["submitted"] == 5
    assert payload["breaker_tripped"]["trip_id"].startswith("qb-")
    assert "recent_poll_cursor" not in payload


def test_coordinator_quarantine_breaker_trips_on_absolute_count(tmp_path: Path):
    """>100 quarantine dalam satu siklus menghentikan siklus meski fraksinya <=1%."""
    from src.runtime.raw_evidence import RawEvidenceConflictError

    service = _stub_service(tmp_path)
    service.ingest_alert.side_effect = RawEvidenceConflictError("slow systemic poison")
    poller = MagicMock()
    t_now = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    all_alerts = _scale_alerts(12000, t_now, step_s=1)
    poison_ids = {f"alert_{i}" for i in range(110)}  # 110/12000 = 0.92% <= 1%

    def _ingest(alert):
        if alert.wazuh_alert_id in poison_ids:
            raise RawEvidenceConflictError("slow systemic poison")
        return []

    service.ingest_alert.side_effect = _ingest
    poller.poll_recent.return_value = all_alerts
    poller.poll_reconciliation.return_value = []
    poller.poll_full_reconciliation.return_value = []
    poller.last_bad_docs = []

    coord = LiveIngestionCoordinator(service=service, poller=poller)
    with pytest.raises(RuntimeError, match="[Qq]uarantine"):
        coord.run_cycle(current_time=t_now)
    # Latch: breaker_tripped tersimpan, key cursor transport TIDAK di-commit.
    assert service.update_live_source_state.called
    payload = service.update_live_source_state.call_args.args[0]
    assert payload["breaker_tripped"]["quarantined"] == 110
    assert payload["breaker_tripped"]["submitted"] == 12000
    assert payload["breaker_tripped"]["trip_id"].startswith("qb-")
    assert "recent_poll_cursor" not in payload


def test_coordinator_quarantine_flushes_once_per_cycle(tmp_path: Path, monkeypatch):
    """Entri quarantine per siklus di-flush lewat satu panggilan add_many."""
    service = create_test_service(tmp_path)
    from src.runtime.raw_evidence import RawAlertEvidenceStore

    service.raw_evidence_store = RawAlertEvidenceStore(db_path=tmp_path / "ev.sqlite3", batch_size=10000)

    t_now = datetime(2026, 8, 28, 10, 30, 0, tzinfo=timezone.utc)
    n = 120
    candidates = _scale_alerts(n, t_now)
    poison_ts = t_now - timedelta(seconds=(n - 77) * 20)
    poison = make_raw_alert(77, poison_ts, level=9, crit=4)
    service.raw_evidence_store.store(poison)
    service.raw_evidence_store.flush()

    poller = MagicMock(spec=WazuhIndexerLivePoller)
    poller.poll_recent.return_value = candidates
    poller.poll_reconciliation.return_value = []
    poller.poll_full_reconciliation.return_value = []

    calls = []
    real_add_many = service.state_manager.quarantine_add_many

    def _counting(entries):
        calls.append(len(entries))
        return real_add_many(entries)

    monkeypatch.setattr(service.state_manager, "quarantine_add_many", _counting)
    coord = LiveIngestionCoordinator(service=service, poller=poller)
    result = coord.run_cycle(current_time=t_now)

    assert result.quarantined == 1
    assert calls == [1]  # tepat satu flush batch


def test_coordinator_quarantine_logs_error_only_on_first_offense(tmp_path: Path, caplog):
    """Quarantine pertama dicatat level error; pengulangan untuk ID yang sama dicatat level debug."""
    import logging

    service = create_test_service(tmp_path)
    from src.runtime.raw_evidence import RawAlertEvidenceStore

    service.raw_evidence_store = RawAlertEvidenceStore(db_path=tmp_path / "ev.sqlite3", batch_size=10000)

    t_now = datetime(2026, 8, 28, 10, 30, 0, tzinfo=timezone.utc)
    n = 120
    candidates = _scale_alerts(n, t_now)
    poison_ts = t_now - timedelta(seconds=(n - 77) * 20)
    poison = make_raw_alert(77, poison_ts, level=9, crit=4)
    service.raw_evidence_store.store(poison)
    service.raw_evidence_store.flush()

    poller = MagicMock(spec=WazuhIndexerLivePoller)
    poller.poll_recent.return_value = candidates
    poller.poll_reconciliation.return_value = []
    poller.poll_full_reconciliation.return_value = []

    coord = LiveIngestionCoordinator(service=service, poller=poller)
    with caplog.at_level(logging.DEBUG, logger="src.runtime.live_coordinator"):
        coord.run_cycle(current_time=t_now)
    assert [r for r in caplog.records if r.levelno >= logging.ERROR and "alert_77" in r.getMessage()]

    caplog.clear()
    t2 = t_now + timedelta(minutes=30)
    with caplog.at_level(logging.DEBUG, logger="src.runtime.live_coordinator"):
        result2 = coord.run_cycle(current_time=t2)
    # alert_77 yang sudah dikarantina dilewati, tidak pernah di-ingest ulang.
    assert result2.quarantined == 0
    assert result2.failures == 0
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR and "Quarantin" in r.getMessage()]
    assert [r for r in caplog.records if r.levelno == logging.DEBUG and "alert_77" in r.getMessage()]


def test_coordinator_buffer_seen_snapshot_single_lookup_per_candidate(tmp_path: Path, monkeypatch):
    """Siklus dengan buffer aktif memanggil is_seen tepat sekali per kandidat."""
    service = create_test_service(tmp_path)
    t_now = datetime(2026, 8, 28, 10, 30, 0, tzinfo=timezone.utc)
    a_seen = make_raw_alert(1, t_now - timedelta(minutes=2))
    a_new = make_raw_alert(2, t_now - timedelta(minutes=1))
    service.ingest_alert(a_seen, auto_persist=False)

    poller = MagicMock(spec=WazuhIndexerLivePoller)
    poller.poll_recent.return_value = [a_seen, a_new]
    poller.poll_reconciliation.return_value = []
    poller.poll_full_reconciliation.return_value = []

    coord = LiveIngestionCoordinator(
        service=service,
        poller=poller,
        order_buffer_enabled=True,
        order_buffer_hold_window=timedelta(hours=1),
    )
    real_is_seen = service.is_seen
    calls = []

    def _counting(alert_id: str) -> bool:
        calls.append(alert_id)
        return real_is_seen(alert_id)

    monkeypatch.setattr(service, "is_seen", _counting)
    coord.run_cycle(current_time=t_now)
    assert sorted(calls) == ["alert_1", "alert_2"]


def test_coordinator_full_retention_duplicates_are_safe(tmp_path: Path):
    """Saat sweep seluruh retensi membaca semua index, alert yang sudah diproses dikenali sebagai duplikat no-op."""
    service = create_test_service(tmp_path)
    poller = MagicMock(spec=WazuhIndexerLivePoller)

    t1 = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    a1 = make_raw_alert(1, t1)
    a2 = make_raw_alert(2, t1 + timedelta(minutes=5))
    a3 = make_raw_alert(3, t1 + timedelta(minutes=10))

    poller.poll_recent.return_value = [a1, a2]
    poller.poll_reconciliation.return_value = []
    poller.poll_full_reconciliation.return_value = []

    coord = LiveIngestionCoordinator(service=service, poller=poller)
    res1 = coord.run_cycle(current_time=t1 + timedelta(minutes=15), force_full_reconciliation=False)
    assert res1.processed_new_ids == 2

    # Sweep seluruh retensi berikutnya mengembalikan a1, a2, dan a3.
    poller.poll_recent.return_value = []
    poller.poll_reconciliation.return_value = []
    poller.poll_full_reconciliation.return_value = [a1, a2, a3]

    res2 = coord.run_cycle(current_time=t1 + timedelta(hours=2), force_full_reconciliation=True)
    assert res2.processed_new_ids == 1
    assert res2.duplicate_noops == 2
    assert service.is_seen("alert_3")


def test_coordinator_persists_transport_state(tmp_path: Path):
    """Coordinator menyimpan state transport (cursor dan timestamp) di state durable service."""
    service = create_test_service(tmp_path)
    poller = MagicMock(spec=WazuhIndexerLivePoller)
    poller.poll_recent.return_value = []
    poller.poll_reconciliation.return_value = []
    poller.poll_full_reconciliation.return_value = []

    t_now = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)
    coord = LiveIngestionCoordinator(service=service, poller=poller)
    coord.run_cycle(current_time=t_now, force_recent_reconciliation=True, force_full_reconciliation=True)

    state = service.get_live_source_state()
    assert state["recent_poll_cursor"] == t_now.isoformat()
    assert state["last_fast_poll_at"] == t_now.isoformat()
    assert state["last_recent_reconciliation_at"] == t_now.isoformat()
    assert state["last_full_reconciliation_at"] == t_now.isoformat()
    assert state["recent_reconciliation_days"] == 2


def test_coordinator_quarantines_deterministic_conflict_and_continues(tmp_path: Path):
    """Kebijakan QUARANTINE: konflik evidence deterministik di tengah siklus dikarantina secara durable;
    kandidat lain tetap di-ingest dan siklus berhasil (cursor di-commit).

    120 kandidat / 1 quarantine (0.83%) masih di bawah batas circuit breaker (>1%).
    """
    from src.runtime.raw_evidence import RawAlertEvidenceStore

    service = create_test_service(tmp_path)
    service.raw_evidence_store = RawAlertEvidenceStore(db_path=tmp_path / "ev.sqlite3", batch_size=10000)

    t_now = datetime(2026, 8, 28, 10, 30, 0, tzinfo=timezone.utc)
    n = 120
    candidates = [
        make_raw_alert(i, t_now - timedelta(seconds=(n - i) * 20))
        for i in range(n)
    ]

    # Simpan dulu isi kanonis yang bertentangan dengan ID alert_77, lalu flush ke SQLite.
    poison_ts = t_now - timedelta(seconds=(n - 77) * 20)
    poison = make_raw_alert(77, poison_ts, level=9, crit=4)
    service.raw_evidence_store.store(poison)
    service.raw_evidence_store.flush()

    poller = MagicMock(spec=WazuhIndexerLivePoller)
    poller.poll_recent.return_value = candidates
    poller.poll_reconciliation.return_value = []
    poller.poll_full_reconciliation.return_value = []

    coord = LiveIngestionCoordinator(service=service, poller=poller)
    result = coord.run_cycle(current_time=t_now)

    assert result.failures == 1
    assert result.quarantined == 1
    assert result.processed_new_ids == n - 1
    assert service.is_seen("alert_0")
    assert service.is_seen("alert_119")

    quarantined = service.state_manager.quarantine_list()
    assert len(quarantined) == 1
    assert quarantined[0]["wazuh_alert_id"] == "alert_77"
    assert quarantined[0]["error_type"] == "RawEvidenceConflictError"
    assert quarantined[0]["count"] == 1

    # Siklus berhasil, jadi cursor transport di-commit (tidak berhenti diam-diam).
    assert coord.last_fast_poll_at == t_now
    assert service.get_live_source_state()["last_fast_poll_at"] == t_now.isoformat()


def test_coordinator_transient_error_still_fails_cycle_without_quarantine(tmp_path: Path):
    """Error ingest sementara (non-deterministik) tetap harus dilempar; cursor tidak boleh maju."""
    service = create_test_service(tmp_path)
    poller = MagicMock(spec=WazuhIndexerLivePoller)

    t_now = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    a1 = make_raw_alert(1, t_now - timedelta(minutes=1))
    poller.poll_recent.return_value = [a1]
    poller.poll_reconciliation.return_value = []
    poller.poll_full_reconciliation.return_value = []

    service.ingest_alert = MagicMock(side_effect=RuntimeError("indexer timeout"))
    coord = LiveIngestionCoordinator(service=service, poller=poller)

    with pytest.raises(RuntimeError, match="indexer timeout"):
        coord.run_cycle(current_time=t_now)

    assert coord.last_fast_poll_at is None
    assert service.state_manager.quarantine_list() == []


def test_full_reconciliation_uses_strict_index_coverage(tmp_path: Path):
    """Sweep seluruh retensi langsung gagal bila ada index yang tidak tersedia (tidak ada celah diam-diam)."""
    service = create_test_service(tmp_path)
    poller = MagicMock(spec=WazuhIndexerLivePoller)
    poller.poll_recent.return_value = []
    poller.poll_reconciliation.return_value = []
    poller.poll_full_reconciliation.return_value = []

    coord = LiveIngestionCoordinator(service=service, poller=poller)
    coord.run_cycle(
        current_time=datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc),
        force_full_reconciliation=True,
    )

    _, kwargs = poller.poll_full_reconciliation.call_args
    assert kwargs.get("allow_unavailable") is False


def test_cycle_records_newest_ingested_event_time(tmp_path: Path):
    """Siklus meng-commit event-time terbaru yang di-ingest untuk telemetri lag yang jujur."""
    service = create_test_service(tmp_path)
    t_now = datetime(2026, 8, 28, 10, 30, 0, tzinfo=timezone.utc)
    a1 = make_raw_alert(1, t_now - timedelta(minutes=2))
    a2 = make_raw_alert(2, t_now - timedelta(minutes=1))
    poller = MagicMock(spec=WazuhIndexerLivePoller)
    poller.poll_recent.return_value = [a1, a2]
    poller.poll_reconciliation.return_value = []
    poller.poll_full_reconciliation.return_value = []

    coord = LiveIngestionCoordinator(service=service, poller=poller)
    coord.run_cycle(current_time=t_now)

    state = service.get_live_source_state()
    assert state.get("newest_ingested_event_time") == (t_now - timedelta(minutes=1)).isoformat()


def test_buffer_skips_seen_ids_without_late_pollution(tmp_path: Path):
    """Duplikat dari rekonsiliasi melewati buffer (tidak mengotori hitungan alert terlambat)."""
    service = create_test_service(tmp_path)
    t_now = datetime(2026, 8, 28, 10, 30, 0, tzinfo=timezone.utc)
    a_seen = make_raw_alert(1, t_now - timedelta(minutes=2))
    a_new = make_raw_alert(2, t_now - timedelta(minutes=1))
    service.ingest_alert(a_seen, auto_persist=False)

    poller = MagicMock(spec=WazuhIndexerLivePoller)
    poller.poll_recent.return_value = [a_seen, a_new]
    poller.poll_reconciliation.return_value = []
    poller.poll_full_reconciliation.return_value = []

    coord = LiveIngestionCoordinator(
        service=service,
        poller=poller,
        order_buffer_enabled=True,
        order_buffer_hold_window=timedelta(hours=1),
    )
    result = coord.run_cycle(current_time=t_now)

    assert result.duplicate_noops == 1
    assert result.processed_new_ids == 0
    assert coord.order_buffer.status()["late_total"] == 0
    assert coord.order_buffer.status()["size"] == 1


def test_persistent_quarantine_skipped_breaker_never_trips(tmp_path: Path, monkeypatch):
    """6 cacat persisten di antara 400 alert selama 20 siklus.

    Kondisi stabil setelah halt pertama: 6 ID itu sudah dikarantina, jadi setiap siklus
    melewatinya (tanpa ingest ulang, tanpa kegagalan, tanpa quarantine baru) —
    breaker tidak pernah trip dan cursor maju di setiap siklus.
    """
    from src.runtime.raw_evidence import RawEvidenceConflictError

    service = _stub_service(tmp_path)
    poison_ids = {f"alert_{i}" for i in range(6)}
    ingest_calls: list = []

    def _ingest(alert):
        ingest_calls.append(alert.wazuh_alert_id)
        if alert.wazuh_alert_id in poison_ids:
            raise RawEvidenceConflictError("persistent poison")
        return []

    service.ingest_alert.side_effect = _ingest
    service.state_manager.quarantine_add_many([
        {"wazuh_alert_id": pid, "source_index": "idx", "source_document_id": pid, "error_type": "RawEvidenceConflictError"}
        for pid in sorted(poison_ids)
    ])

    poller = MagicMock()
    t0 = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    alerts = _scale_alerts(400, t0)
    poller.poll_recent.return_value = alerts
    poller.poll_reconciliation.return_value = []
    poller.poll_full_reconciliation.return_value = []
    poller.last_bad_docs = []

    real_id_set = service.state_manager.quarantine_id_set
    list_calls: list = []

    def _counting_list():
        list_calls.append(1)
        return real_id_set()

    monkeypatch.setattr(service.state_manager, "quarantine_id_set", _counting_list)
    real_add_many = service.state_manager.quarantine_add_many
    add_many_calls: list = []

    def _counting_add(entries):
        add_many_calls.append(len(entries))
        return real_add_many(entries)

    monkeypatch.setattr(service.state_manager, "quarantine_add_many", _counting_add)

    coord = LiveIngestionCoordinator(service=service, poller=poller)
    for cycle in range(20):
        result = coord.run_cycle(current_time=t0 + timedelta(minutes=cycle))

    assert result.failures == 0
    assert result.quarantined == 0
    assert result.skipped_quarantined == 6
    assert result.processed_new_ids == 394
    assert coord.last_fast_poll_at == t0 + timedelta(minutes=19)
    assert service.state_manager.quarantine_count() == 6
    assert set(ingest_calls).isdisjoint(poison_ids)  # tidak pernah di-ingest ulang
    assert add_many_calls == []  # tidak ada yang baru untuk di-flush
    assert len(list_calls) == 20  # tepat satu query snapshot quarantine per siklus


def test_breaker_counts_only_new_quarantines(tmp_path: Path):
    """Quarantine yang benar-benar baru tetap memicu breaker (6 baru / 400 = 1.5% > 1%),
    membuktikan penghitungan khusus yang baru tidak mematikan proteksi.
    """
    from src.runtime.raw_evidence import RawEvidenceConflictError

    service = _stub_service(tmp_path)
    poison_ids = {f"alert_{i}" for i in range(6)}

    def _ingest(alert):
        if alert.wazuh_alert_id in poison_ids:
            raise RawEvidenceConflictError("fresh systemic poison")
        return []

    service.ingest_alert.side_effect = _ingest
    poller = MagicMock()
    t_now = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    poller.poll_recent.return_value = _scale_alerts(400, t_now)
    poller.poll_reconciliation.return_value = []
    poller.poll_full_reconciliation.return_value = []
    poller.last_bad_docs = []

    coord = LiveIngestionCoordinator(service=service, poller=poller)
    with pytest.raises(RuntimeError, match="[Qq]uarantine"):
        coord.run_cycle(current_time=t_now)
    # Latch: breaker_tripped tersimpan, key cursor transport TIDAK di-commit.
    assert service.update_live_source_state.called
    payload = service.update_live_source_state.call_args.args[0]
    assert payload["breaker_tripped"]["quarantined"] == 6
    assert payload["breaker_tripped"]["submitted"] == 400
    assert payload["breaker_tripped"]["trip_id"].startswith("qb-")
    assert "recent_poll_cursor" not in payload


def test_future_dated_alert_does_not_shift_newest(tmp_path: Path):
    """newest_ingested_event_time mengabaikan kandidat dari masa depan (> now + 5 menit)
    meski kandidat itu berhasil di-ingest.
    """
    service = _stub_service(tmp_path)
    service.ingest_alert.side_effect = lambda a: []
    captured: dict = {}
    service.update_live_source_state.side_effect = lambda s: captured.update(s)

    t_now = datetime(2026, 8, 28, 10, 30, 0, tzinfo=timezone.utc)
    a_ok = make_raw_alert(1, t_now - timedelta(minutes=2))
    a_future = make_raw_alert(2, t_now + timedelta(hours=1))
    poller = MagicMock()
    poller.poll_recent.return_value = [a_ok, a_future]
    poller.poll_reconciliation.return_value = []
    poller.poll_full_reconciliation.return_value = []
    poller.last_bad_docs = []

    coord = LiveIngestionCoordinator(service=service, poller=poller)
    result = coord.run_cycle(current_time=t_now)

    assert result.processed_new_ids == 2
    assert captured["newest_ingested_event_time"] == (t_now - timedelta(minutes=2)).isoformat()


def test_all_future_dated_writes_explicit_none(tmp_path: Path):
    """Tanpa kandidat non-masa-depan yang bisa di-ingest, key ditulis sebagai None eksplisit,
    bukan nilai basi dari siklus sebelumnya.
    """
    service = _stub_service(tmp_path)
    service.ingest_alert.side_effect = lambda a: []
    captured: dict = {}
    service.update_live_source_state.side_effect = lambda s: captured.update(s)

    t_now = datetime(2026, 8, 28, 10, 30, 0, tzinfo=timezone.utc)
    poller = MagicMock()
    poller.poll_recent.return_value = [make_raw_alert(1, t_now + timedelta(hours=1))]
    poller.poll_reconciliation.return_value = []
    poller.poll_full_reconciliation.return_value = []
    poller.last_bad_docs = []

    coord = LiveIngestionCoordinator(service=service, poller=poller)
    coord.run_cycle(current_time=t_now)

    assert "newest_ingested_event_time" in captured
    assert captured["newest_ingested_event_time"] is None


def test_quarantined_candidate_excluded_from_newest(tmp_path: Path):
    """Kandidat dengan timestamp terbaru yang dikarantina tidak boleh menggeser
    newest_ingested_event_time; yang dipakai adalah maksimum dari yang berhasil di-ingest.
    """
    from src.runtime.raw_evidence import RawEvidenceConflictError

    service = _stub_service(tmp_path)

    def _ingest(alert):
        if alert.wazuh_alert_id == "alert_999":
            raise RawEvidenceConflictError("newest is poison")
        return []

    service.ingest_alert.side_effect = _ingest
    captured: dict = {}
    service.update_live_source_state.side_effect = lambda s: captured.update(s)

    t_now = datetime(2026, 8, 28, 10, 30, 0, tzinfo=timezone.utc)
    oks = [
        make_raw_alert(i, t_now - timedelta(hours=2) - timedelta(seconds=i * 20))
        for i in range(150)
    ]
    poison = make_raw_alert(999, t_now - timedelta(minutes=1))
    poller = MagicMock()
    poller.poll_recent.return_value = oks + [poison]
    poller.poll_reconciliation.return_value = []
    poller.poll_full_reconciliation.return_value = []
    poller.last_bad_docs = []

    coord = LiveIngestionCoordinator(service=service, poller=poller)
    result = coord.run_cycle(current_time=t_now)

    assert result.quarantined == 1
    assert captured["newest_ingested_event_time"] == (t_now - timedelta(hours=2)).isoformat()


def test_breaker_latch_halts_cycles_until_matching_ack(tmp_path: Path):
    """Jangka panjang: burst 30% memicu trip di siklus 1 dan latch; siklus 2-3 langsung error karena
    latch tanpa bekerja; ack yang salah tetap error; ack yang cocok melanjutkan siklus.
    """
    from src.runtime.raw_evidence import RawEvidenceConflictError

    service = _stub_service(tmp_path)
    store: dict = {}
    service.get_live_source_state.side_effect = lambda: dict(store)
    service.update_live_source_state.side_effect = lambda s: store.update(s)
    poison_ids = {f"alert_{i}" for i in range(30)}

    def _ingest(alert):
        if alert.wazuh_alert_id in poison_ids:
            raise RawEvidenceConflictError("burst poison")
        return []

    service.ingest_alert.side_effect = _ingest
    poller = MagicMock()
    t_now = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    poller.poll_recent.return_value = _scale_alerts(100, t_now)
    poller.poll_reconciliation.return_value = []
    poller.poll_full_reconciliation.return_value = []
    poller.last_bad_docs = []

    coord = LiveIngestionCoordinator(service=service, poller=poller)
    with pytest.raises(RuntimeError, match="[Qq]uarantine"):
        coord.run_cycle(current_time=t_now)
    latch = store.get("breaker_tripped")
    assert isinstance(latch, dict)
    trip_id = latch["trip_id"]
    assert trip_id.startswith("qb-")
    assert latch["quarantined"] == 30
    assert latch["submitted"] == 100
    assert latch.get("at")
    assert service.state_manager.quarantine_count() == 30  # flush tetap tersimpan meski halt

    for step in (5, 10):
        service.ingest_alert.reset_mock()
        poller.poll_recent.reset_mock()
        with pytest.raises(RuntimeError, match="[Bb]reaker.*[Tt]rip|ack"):
            coord.run_cycle(current_time=t_now + timedelta(minutes=step))
        service.ingest_alert.assert_not_called()
        poller.poll_recent.assert_not_called()

    wrong_ack_coord = LiveIngestionCoordinator(
        service=service, poller=poller, breaker_ack="qb-20000101000000-0"
    )
    with pytest.raises(RuntimeError, match="[Bb]reaker.*[Tt]rip|ack"):
        wrong_ack_coord.run_cycle(current_time=t_now + timedelta(minutes=15))

    ack_coord = LiveIngestionCoordinator(service=service, poller=poller, breaker_ack=trip_id)
    poller.poll_recent.return_value = _scale_alerts(100, t_now + timedelta(minutes=20), start=1000)
    service.ingest_alert.side_effect = lambda a: []
    result = ack_coord.run_cycle(current_time=t_now + timedelta(minutes=20))
    assert result.processed_new_ids == 100
    assert store.get("breaker_tripped") is None


def test_skip_quarantined_before_buffer_never_buffered(tmp_path: Path):
    """ID yang dikarantina disaring sebelum OrderBuffer.add sehingga buffer tidak pernah menahannya;
    penyaringan ini terlihat lewat skipped_quarantined.
    """
    service = _stub_service(tmp_path)
    service.ingest_alert.side_effect = lambda a: []
    service.state_manager.quarantine_add("alert_1", error_type="E1")
    poller = MagicMock()
    t_now = datetime(2026, 8, 28, 10, 30, 0, tzinfo=timezone.utc)
    poller.poll_recent.return_value = [
        make_raw_alert(1, t_now - timedelta(minutes=2)),
        make_raw_alert(2, t_now - timedelta(minutes=1)),
    ]
    poller.poll_reconciliation.return_value = []
    poller.poll_full_reconciliation.return_value = []
    poller.last_bad_docs = []

    coord = LiveIngestionCoordinator(
        service=service,
        poller=poller,
        order_buffer_enabled=True,
        order_buffer_hold_window=timedelta(hours=1),
    )
    result = coord.run_cycle(current_time=t_now)

    assert result.skipped_quarantined == 1
    assert coord.order_buffer._held_ids == {"alert_2"}
    tried = [c.args[0].wazuh_alert_id for c in service.ingest_alert.call_args_list]
    assert "alert_1" not in tried


def test_unidentified_bad_doc_key_is_content_hash(tmp_path: Path):
    """Dokumen buruk tanpa doc_id diberi kunci sha256(content)[:12] — stabil antar siklus
    (tanpa akhiran :pos), sehingga pengulangannya dilewati, bukan dikarantina ulang.
    """
    import hashlib
    import json as _json

    service = _stub_service(tmp_path)
    service.ingest_alert.side_effect = lambda a: []
    poller = MagicMock()
    t_now = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    valid = _scale_alerts(150, t_now)
    bad = {"index": "wazuh-alerts-4.x-2026.08.28", "doc_id": None, "error": "boom"}
    poller.poll_recent.side_effect = lambda **k: (setattr(poller, "last_bad_docs", [dict(bad)]) or valid)
    poller.poll_reconciliation.side_effect = lambda **k: (setattr(poller, "last_bad_docs", []) or [])
    poller.poll_full_reconciliation.side_effect = lambda **k: (setattr(poller, "last_bad_docs", []) or [])
    poller.last_bad_docs = []

    coord = LiveIngestionCoordinator(service=service, poller=poller)
    coord.run_cycle(current_time=t_now)
    rows = service.state_manager.quarantine_list()
    assert len(rows) == 1
    # Kunci hanya meng-hash {index, doc_id} — page_pos yang ada di teks error tidak ikut,
    # sehingga kunci stabil antar siklus.
    expected = "unidentified:" + hashlib.sha256(
        _json.dumps(
            {"index": "wazuh-alerts-4.x-2026.08.28", "doc_id": None},
            sort_keys=True,
            default=str,
        ).encode("utf-8")
    ).hexdigest()[:12]
    assert rows[0]["wazuh_alert_id"] == expected

    # Dokumen identik yang di-poll ulang di page_pos berbeda (teks error berbeda)
    # mendapat kunci YANG SAMA: dilewati, bukan dikarantina ulang.
    bad2 = {"index": "wazuh-alerts-4.x-2026.08.28", "doc_id": None, "error": "boom (page_pos=7)"}
    poller.poll_recent.side_effect = lambda **k: (setattr(poller, "last_bad_docs", [dict(bad2)]) or valid)
    result2 = coord.run_cycle(current_time=t_now + timedelta(minutes=5))
    assert result2.quarantined == 0
    assert result2.failures == 0
    assert service.state_manager.quarantine_count() == 1
    assert service.state_manager.quarantine_list()[0]["count"] == 1
