"""Unit test arsip JSONL live: penulis dataset replay mentah per alert + hook di coordinator."""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.contracts.raw_alert import CanonicalRawAlert
from src.etl.wazuh_canonicalizer import canonicalize_wazuh_alert


def make_live_like_alert(idx: int, ts: datetime, with_envelope: bool = True) -> CanonicalRawAlert:
    meta: dict = {
        "rule_description": "SSHD brute force",
        "rule_groups_all": ["sshd", "authentication_failed"],
        "location": "/var/log/auth.log",
        "full_log": "Failed password for root from 192.0.2.10",
        "decoder": "sshd",
        "manager": {"name": "wazuh-manager"},
        "data": {"srcip": "192.0.2.10", "dstuser": "root"},
    }
    if with_envelope:
        meta["source_index"] = "wazuh-alerts-4.x-2026.09.28"
        meta["source_document_id"] = f"doc-{idx}"
    return CanonicalRawAlert(
        wazuh_alert_id=f"1787895525.{48400 + idx}",
        timestamp=ts,
        agent_id="001",
        agent_name="soc-1",
        rule_group_primary="authentication_failed",
        rule_level=10,
        rule_id="5760",
        mitre_tactics=("Credential Access",),
        srcip="192.0.2.10",
        agent_criticality=2,
        metadata=meta,
    )


def test_build_archive_record_round_trip():
    from src.runtime.live_archive import build_archive_record

    ts = datetime(2026, 9, 28, 8, 0, 0, tzinfo=timezone.utc)
    alert = make_live_like_alert(1, ts)
    record = build_archive_record(alert)

    line = json.dumps(record)
    back = canonicalize_wazuh_alert(json.loads(line))

    assert back.wazuh_alert_id == alert.wazuh_alert_id
    assert back.timestamp == alert.timestamp
    assert back.agent_id == alert.agent_id
    assert back.agent_name == alert.agent_name
    assert back.rule_id == alert.rule_id
    assert back.rule_level == alert.rule_level
    assert back.rule_group_primary == alert.rule_group_primary
    assert back.srcip == alert.srcip
    assert back.mitre_tactics == alert.mitre_tactics


def test_build_archive_record_plain_body_without_envelope():
    from src.runtime.live_archive import build_archive_record

    ts = datetime(2026, 9, 28, 8, 0, 0, tzinfo=timezone.utc)
    alert = make_live_like_alert(1, ts, with_envelope=False)
    record = build_archive_record(alert)

    assert "_source" not in record
    back = canonicalize_wazuh_alert(json.loads(json.dumps(record)))
    assert back.wazuh_alert_id == alert.wazuh_alert_id


def test_append_alerts_sorted_and_valid_lines(tmp_path: Path):
    from src.runtime.live_archive import append_alerts

    base = datetime(2026, 9, 28, 8, 0, 0, tzinfo=timezone.utc)
    alerts = [
        make_live_like_alert(3, base + timedelta(minutes=3)),
        make_live_like_alert(1, base + timedelta(minutes=1)),
        make_live_like_alert(2, base + timedelta(minutes=2)),
    ]
    written = append_alerts(alerts, tmp_path / "archive")
    assert written == 3

    target = tmp_path / "archive" / "live-20260928.jsonl"
    assert target.is_file()
    lines = target.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    ids = [canonicalize_wazuh_alert(json.loads(line)).wazuh_alert_id for line in lines]
    assert ids == sorted(ids, key=lambda v: v)


def test_append_alerts_daily_rotation(tmp_path: Path):
    from src.runtime.live_archive import append_alerts

    alerts = [
        make_live_like_alert(1, datetime(2026, 9, 28, 23, 59, 0, tzinfo=timezone.utc)),
        make_live_like_alert(2, datetime(2026, 9, 29, 0, 1, 0, tzinfo=timezone.utc)),
    ]
    assert append_alerts(alerts, tmp_path / "archive") == 2
    assert (tmp_path / "archive" / "live-20260928.jsonl").is_file()
    assert (tmp_path / "archive" / "live-20260929.jsonl").is_file()


def test_append_never_raises_on_write_failure(tmp_path: Path):
    from src.runtime.live_archive import append_alert, append_alerts

    blocker = tmp_path / "blocker"
    blocker.write_text("not a dir", encoding="utf-8")
    ts = datetime(2026, 9, 28, 8, 0, 0, tzinfo=timezone.utc)
    alert = make_live_like_alert(1, ts)

    assert append_alert(alert, blocker / "sub") is None
    assert append_alerts([alert], blocker / "sub") == 0


def _stub_coordinator(tmp_path: Path, alerts, **kwargs):
    from unittest.mock import MagicMock

    from src.runtime.live_coordinator import LiveIngestionCoordinator

    service = MagicMock()
    service.get_live_source_state.return_value = {}
    service.is_seen.return_value = False
    service.ingest_alert.return_value = []
    service.check_idle_flush.return_value = []
    service.state_manager.quarantine_id_set.return_value = set()

    poller = MagicMock()
    poller.poll_recent.return_value = alerts
    poller.poll_reconciliation.return_value = []
    poller.poll_full_reconciliation.return_value = []

    coord = LiveIngestionCoordinator(service=service, poller=poller, **kwargs)
    return coord, service


def test_run_cycle_archives_new_alerts_when_enabled(tmp_path: Path):
    base = datetime(2026, 9, 28, 8, 0, 0, tzinfo=timezone.utc)
    alerts = [make_live_like_alert(2, base + timedelta(minutes=2)),
              make_live_like_alert(1, base + timedelta(minutes=1))]
    archive_dir = tmp_path / "archive"
    coord, _ = _stub_coordinator(
        tmp_path, alerts,
        live_archive_enabled=True, live_archive_dir=archive_dir,
    )

    result = coord.run_cycle(current_time=base + timedelta(minutes=5))

    assert result.processed_new_ids == 2
    target = archive_dir / "live-20260928.jsonl"
    assert target.is_file()
    lines = target.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    for line in lines:
        back = canonicalize_wazuh_alert(json.loads(line))
        assert back.wazuh_alert_id.startswith("1787895525.")


def test_run_cycle_skips_archive_for_duplicates(tmp_path: Path):
    from unittest.mock import MagicMock

    from src.runtime.live_coordinator import LiveIngestionCoordinator

    base = datetime(2026, 9, 28, 8, 0, 0, tzinfo=timezone.utc)
    alert = make_live_like_alert(1, base)
    archive_dir = tmp_path / "archive"

    service = MagicMock()
    service.get_live_source_state.return_value = {}
    service.is_seen.return_value = True  # sudah seen -> duplikat noop
    service.ingest_alert.return_value = []
    service.check_idle_flush.return_value = []
    service.state_manager.quarantine_id_set.return_value = set()
    poller = MagicMock()
    poller.poll_recent.return_value = [alert]
    poller.poll_reconciliation.return_value = []
    poller.poll_full_reconciliation.return_value = []

    coord = LiveIngestionCoordinator(
        service=service, poller=poller,
        live_archive_enabled=True, live_archive_dir=archive_dir,
    )
    result = coord.run_cycle(current_time=base + timedelta(minutes=5))

    assert result.duplicate_noops == 1
    assert not (archive_dir / "live-20260928.jsonl").exists()


def test_run_cycle_archive_failure_does_not_fail_cycle(tmp_path: Path):
    blocker = tmp_path / "blocker"
    blocker.write_text("not a dir", encoding="utf-8")
    base = datetime(2026, 9, 28, 8, 0, 0, tzinfo=timezone.utc)
    coord, _ = _stub_coordinator(
        tmp_path, [make_live_like_alert(1, base)],
        live_archive_enabled=True, live_archive_dir=blocker / "sub",
    )

    result = coord.run_cycle(current_time=base + timedelta(minutes=5))

    assert result.processed_new_ids == 1
    assert result.failures == 0


def test_run_cycle_archive_disabled_by_default(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("RBTA_LIVE_ARCHIVE_ENABLED", raising=False)
    monkeypatch.delenv("RBTA_LIVE_ARCHIVE_DIR", raising=False)
    base = datetime(2026, 9, 28, 8, 0, 0, tzinfo=timezone.utc)
    coord, _ = _stub_coordinator(tmp_path, [make_live_like_alert(1, base)])

    assert coord.live_archive_enabled is False
    coord.run_cycle(current_time=base + timedelta(minutes=5))
    assert list(tmp_path.glob("**/live-*.jsonl")) == []

