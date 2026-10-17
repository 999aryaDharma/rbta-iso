"""T4: agen yang dikecualikan (RBTA_EXCLUDED_AGENTS) tidak menghasilkan meta-alert, counter naik."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

from src.contracts.raw_alert import CanonicalRawAlert
from src.runtime.live_coordinator import LiveIngestionCoordinator
from src.runtime.live_source import WazuhIndexerLivePoller
from src.runtime.raw_evidence import RawAlertEvidenceStore
from tests.unit.runtime.test_live_coordinator import create_test_service

NOW = datetime(2026, 10, 17, 10, 0, tzinfo=timezone.utc)


def _alert(idx: int, agent_id: str, agent_name: str, minutes_ago: float) -> CanonicalRawAlert:
    return CanonicalRawAlert(
        wazuh_alert_id=f"ex_{idx}",
        timestamp=NOW - timedelta(minutes=minutes_ago),
        agent_id=agent_id,
        agent_name=agent_name,
        rule_group_primary="pam",
        rule_level=5,
        rule_id="5501",
        mitre_tactics=(),
        srcip=None,
        agent_criticality=1,
    )


def _coordinator(tmp_path: Path, alerts, excluded: str):
    service = create_test_service(tmp_path)
    service.raw_evidence_store = RawAlertEvidenceStore(tmp_path / "evidence.sqlite3")
    poller = MagicMock(spec=WazuhIndexerLivePoller)
    poller.poll_recent.return_value = alerts
    poller.poll_reconciliation.return_value = alerts
    poller.poll_full_reconciliation.return_value = []
    return service, LiveIngestionCoordinator(service=service, poller=poller, excluded_agents=excluded)


def test_excluded_agent_alerts_never_reach_rbta_and_are_counted(tmp_path: Path):
    alerts = [
        _alert(1, "001", "soc-1", 5),
        _alert(2, "009", "Agent-Test", 4),  # cocok lewat nama (case-insensitive)
        _alert(3, "010", "unknown", 3),  # cocok lewat agent_id
        _alert(4, "009", "agent-test", 2),
    ]
    service, coord = _coordinator(tmp_path, alerts, excluded=" agent-test , 010 ")

    result = coord.run_cycle(current_time=NOW)
    service.drain_and_score()

    assert result.excluded == 3
    assert result.submitted_candidates == 1
    assert service.is_seen("ex_1")
    for aid in ("ex_2", "ex_3", "ex_4"):
        assert not service.is_seen(aid)
        assert service.raw_evidence_store.get(aid) is None
    members = {aid for s in service.get_history() for aid in s.source_alert_ids}
    assert members == {"ex_1"}
    assert {s.agent_id for s in service.get_history()} == {"001"}
    assert service.state_manager.excluded_counts() == {"010": 1, "agent-test": 2}

    # Poll ulang (rekonsiliasi) atas alert yang sama tidak menggandakan counter.
    coord.run_cycle(current_time=NOW + timedelta(seconds=5), force_recent_reconciliation=True)
    assert sum(service.state_manager.excluded_counts().values()) == 3


def test_no_exclusion_by_default(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("RBTA_EXCLUDED_AGENTS", raising=False)
    service, coord = _coordinator(tmp_path, [_alert(1, "009", "agent-test", 1)], excluded=None)
    assert coord.excluded_agents == frozenset()
    assert coord.run_cycle(current_time=NOW).excluded == 0
    assert service.is_seen("ex_1")
    assert service.state_manager.excluded_counts() == {}


def test_live_status_exposes_excluded_counters(tmp_path: Path):
    from types import SimpleNamespace

    from fastapi.testclient import TestClient

    from src.api.app import create_app

    service, coord = _coordinator(tmp_path, [_alert(2, "009", "agent-test", 1)], excluded="agent-test")
    coord.run_cycle(current_time=NOW)
    app = create_app(service=service, api_key="k")
    app.state.live_worker = SimpleNamespace(status=lambda: {"alive": True}, coordinator=coord)
    body = TestClient(app).get("/api/v1/live/status", headers={"Authorization": "Bearer k"}).json()
    assert body["excluded_agents"] == ["agent-test"]
    assert body["excluded_alerts_total"] == {"agent-test": 1}
