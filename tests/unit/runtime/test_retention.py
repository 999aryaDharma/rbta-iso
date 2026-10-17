"""T12: retensi data live, guard re-ingest, pemakaian disk, dan pemangkasan seen yang berurutan."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
from unittest.mock import MagicMock

from src.contracts.raw_alert import CanonicalRawAlert
from src.runtime.live_coordinator import LiveIngestionCoordinator
from src.runtime.live_source import WazuhIndexerLivePoller
from src.runtime.raw_evidence import RawAlertEvidenceStore
from src.runtime.retention import disk_usage, prune
from src.runtime.service import _RecentIdSet
from tests.unit.runtime.test_live_coordinator import create_test_service

NOW = datetime(2026, 10, 17, 3, 30, tzinfo=timezone.utc)


def _alert(aid: str, ts: datetime) -> CanonicalRawAlert:
    return CanonicalRawAlert(wazuh_alert_id=aid, timestamp=ts, agent_id="001", agent_name="soc-1",
                             rule_group_primary="pam", rule_level=5, rule_id="5501", mitre_tactics=(),
                             srcip=None, agent_criticality=1)


def test_prune_removes_only_expired_rows_and_files(tmp_path: Path):
    service = create_test_service(tmp_path)
    store = RawAlertEvidenceStore(tmp_path / "evidence.sqlite3")
    old, new = NOW - timedelta(days=100), NOW - timedelta(days=10)
    store.store(_alert("old", old))
    store.store(_alert("new", new))
    with sqlite3.connect(service.state_manager.history_db_path) as conn:
        conn.execute("INSERT INTO seen_alert_ids (wazuh_alert_id, inserted_at) VALUES ('old', ?)",
                     (old.strftime("%Y-%m-%d %H:%M:%S"),))
        conn.execute("INSERT INTO seen_alert_ids (wazuh_alert_id, inserted_at) VALUES ('new', ?)",
                     (new.strftime("%Y-%m-%d %H:%M:%S"),))
        conn.execute("INSERT INTO finalized_history (meta_id, scored_data) VALUES (1, '{}')")
    archive = tmp_path / "archive"
    archive.mkdir()
    for name in ("live-20260701.jsonl", "live-20261010.jsonl", "notes.txt"):
        (archive / name).write_text("x", encoding="utf-8")

    result = prune(service.state_manager, store, archive, NOW, 90, vacuum=True)

    assert (result["raw_evidence"], result["seen_alert_ids"], result["archive_files"], result["vacuumed"]) == (1, 1, 1, True)
    assert store.get("old") is None and store.get("new") is not None and store.count() == 1
    assert service.state_manager.has_seen_alert_id("new") and not service.state_manager.has_seen_alert_id("old")
    assert sorted(p.name for p in archive.iterdir()) == ["live-20261010.jsonl", "notes.txt"]
    assert service.state_manager.get_finalized(1) == {}  # MetaAlert final tidak dipangkas


def test_zero_days_disables_pruning(tmp_path: Path):
    service = create_test_service(tmp_path)
    assert prune(service.state_manager, None, None, NOW, 0)["cutoff"] is None


def test_coordinator_skips_alerts_older_than_retention(tmp_path: Path):
    service = create_test_service(tmp_path)
    poller = MagicMock(spec=WazuhIndexerLivePoller)
    alerts = [_alert("expired", NOW - timedelta(days=91)), _alert("fresh", NOW - timedelta(minutes=1))]
    poller.poll_recent.return_value = alerts
    poller.poll_reconciliation.return_value = []
    poller.poll_full_reconciliation.return_value = alerts
    coord = LiveIngestionCoordinator(service=service, poller=poller, retention_days=90)
    result = coord.run_cycle(current_time=NOW)
    assert result.retention_expired == 1
    assert service.is_seen("fresh") and not service.is_seen("expired")
    assert service.get_live_source_state()["retention_expired_last_cycle"] == 1


def test_disk_usage_reports_warning_flag(tmp_path: Path):
    usage = disk_usage(tmp_path)
    assert usage is not None and 0 <= usage["used_pct"] <= 100
    assert usage["warning"] == (usage["used_pct"] > 80)
    assert disk_usage(tmp_path / "missing") is None


def test_recent_id_set_drops_oldest_not_random():
    ids = _RecentIdSet()
    for i in range(10_005):
        ids.add(f"id-{i}")
    ids.add("id-0")  # sudah ada: urutan sisip pertama dipertahankan
    ids.keep_newest(10_000)
    assert len(ids) == 10_000
    assert "id-4" not in ids and "id-5" in ids and "id-10004" in ids
    assert ids == {f"id-{i}" for i in range(5, 10_005)}


def test_service_trim_keeps_dedup_semantics(tmp_path: Path):
    service = create_test_service(tmp_path)
    assert isinstance(service.engine._seen_alert_ids, _RecentIdSet)
    service.engine._seen_alert_ids.keep_newest(0)  # simulasi hot cache kosong
    first = _alert("dup", NOW)
    service.ingest_alert(first)
    service.engine._seen_alert_ids.keep_newest(0)
    # Tetap dedup lewat store durable meski hot cache sudah dipangkas.
    assert service.ingest_alert(first) == [] and service.is_seen("dup")
    assert [b["alert_count"] for b in service.engine.snapshot_buckets()] == [1]
