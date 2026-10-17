"""T6: CSV bukti harian dari state sintetis berisi angka yang benar."""

import csv
from datetime import date, datetime, time, timedelta, timezone
import json
from pathlib import Path
import sqlite3

from fastapi.testclient import TestClient

from src.api.app import create_app
from src.contracts.raw_alert import CanonicalRawAlert
from src.runtime.durable_state import DurableStateManager
from src.runtime.evidence_export import WITA, DailyJob, export_day, wita_day_bounds
from src.runtime.raw_evidence import RawAlertEvidenceStore

DAY = date(2026, 10, 16)
# 2026-10-16 WITA = [2026-10-15T16:00Z, 2026-10-16T16:00Z)
T0 = datetime(2026, 10, 15, 17, 0, tzinfo=timezone.utc)


def _alert(aid: str, agent: str, ts: datetime) -> CanonicalRawAlert:
    return CanonicalRawAlert(
        wazuh_alert_id=aid, timestamp=ts, agent_id={"web-1": "001", "db-1": "002"}.get(agent, "009"),
        agent_name=agent, rule_group_primary="pam", rule_level=5, rule_id="5501",
        mitre_tactics=(), srcip=None, agent_criticality=1,
    )


def _features(v: float) -> dict:
    keys = ("max_severity", "mitre_tactic_count", "critical_mitre_tactic_present", "alert_count_log",
            "rule_diversity_shannon", "severity_dispersion", "agent_criticality")
    return {k: v for k in keys}


def _build_state(tmp_path: Path):
    manager = DurableStateManager(tmp_path / "state.json")
    store = RawAlertEvidenceStore(tmp_path / "evidence.sqlite3")
    raw = [
        ("r1", "web-1", T0, 10), ("r2", "web-1", T0 + timedelta(minutes=1), 30),
        ("r3", "db-1", T0 + timedelta(minutes=2), 20), ("r4", "db-1", T0 + timedelta(minutes=3), 40),
        # Hari lain (2026-10-16T16:00Z = 17 Okt 00:00 WITA): tidak dihitung.
        ("r5", "db-1", datetime(2026, 10, 16, 16, 0, tzinfo=timezone.utc), 5),
    ]
    for aid, agent, ts, _ in raw:
        store.store(_alert(aid, agent, ts))
    store.flush()
    with sqlite3.connect(store.db_path) as conn:
        for aid, _, ts, lag in raw:
            conn.execute("UPDATE raw_alert_evidence SET ingested_at=? WHERE wazuh_alert_id=?",
                         ((ts + timedelta(seconds=lag)).isoformat(), aid))

    metas = [  # (meta_id, agent, action, decision, end_time, feature value, finalized lag, sent lag)
        (1, "web-1", "ESCALATE", "CRITICAL", T0 + timedelta(minutes=1), 1.0, 60, 2),
        (2, "db-1", "DAILY_DIGEST", "NOISE_HIGH", T0 + timedelta(minutes=3), 2.0, 120, None),
        (3, "db-1", "SUPPRESS", "CONTEXTUAL_ANOMALY", T0 + timedelta(minutes=3), 3.0, 180, None),
    ]
    with sqlite3.connect(manager.history_db_path) as conn:
        for mid, agent, action, decision, end, val, fin_lag, sent_lag in metas:
            data = {"meta_id": mid, "agent_id": "x", "agent_name": agent, "action": action, "decision": decision,
                    "end_time": end.isoformat(), "model_version": "rbta-if-thesis-v1", "seven_features": _features(val)}
            fin = end + timedelta(seconds=fin_lag)
            conn.execute("INSERT INTO finalized_history (meta_id, scored_data, finalized_at) VALUES (?, ?, ?)",
                         (mid, json.dumps(data), fin.isoformat()))
            if sent_lag is not None:
                conn.execute("INSERT INTO notification_log (meta_id, run_id, verdict, sent_at) VALUES (?, 'live', 'SENT', ?)",
                             (mid, (fin + timedelta(seconds=sent_lag)).isoformat()))
        conn.execute("INSERT INTO quarantined_alerts (wazuh_alert_id, first_seen, last_seen) VALUES ('q1', ?, ?)",
                     ((T0 + timedelta(hours=1)).isoformat(), (T0 + timedelta(hours=1)).isoformat()))
    manager.excluded_add_many([_alert("x1", "agent-test", T0), _alert("x2", "agent-test", T0 - timedelta(days=2))])
    source_state = {"live_worker_start_log": [(T0 + timedelta(hours=2)).isoformat(), "2026-10-01T00:00:00+00:00"]}
    return manager, store, source_state


def _read(path: Path):
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def test_day_bounds_are_wita():
    assert wita_day_bounds(DAY) == ("2026-10-15T16:00:00+00:00", "2026-10-16T16:00:00+00:00")


def test_export_day_writes_correct_numbers(tmp_path: Path):
    manager, store, source_state = _build_state(tmp_path)
    identity = {"version": "rbta-if-thesis-v1", "sha256": "abc"}
    out = tmp_path / "evidence"
    export_day(manager, store.db_path, out, DAY, identity, source_state)
    export_day(manager, store.db_path, out, DAY, identity, source_state)  # idempoten

    (summary,) = _read(out / "daily_summary.csv")
    assert summary["date"] == "2026-10-16"
    assert (summary["model_version"], summary["model_sha256"]) == ("rbta-if-thesis-v1", "abc")
    assert (summary["raw_alerts"], summary["excluded_alerts"], summary["meta_alerts"]) == ("4", "1", "3")
    assert float(summary["arr"]) == 25.0
    assert (summary["n_escalate"], summary["n_digest"], summary["n_suppress"], summary["n_contextual"]) == ("1", "1", "1", "1")
    assert summary["quarantined"] == "1"
    assert float(summary["event_lag_p50"]) == 25.0  # median(10, 30, 20, 40)
    assert float(summary["event_lag_p95"]) == 38.5
    assert float(summary["finalize_latency_p50"]) == 120.0
    assert float(summary["dispatch_latency_p50"]) == float(summary["dispatch_latency_p95"]) == 2.0
    assert summary["worker_restarts"] == "1"

    per_agent = _read(out / "daily_per_agent.csv")
    assert per_agent == [
        {"date": "2026-10-16", "agent": "db-1", "raw": "2", "meta": "2", "escalate": "0", "digest": "1", "suppress": "1"},
        {"date": "2026-10-16", "agent": "web-1", "raw": "2", "meta": "1", "escalate": "1", "digest": "0", "suppress": "0"},
    ]

    quantiles = _read(out / "feature_quantiles_live.csv")
    assert len(quantiles) == 7
    row = quantiles[0]
    assert (row["n"], float(row["q1"]), float(row["median"]), float(row["q3"]), float(row["p95"])) == ("3", 1.5, 2.0, 2.5, 2.9)


def test_empty_day_has_no_arr(tmp_path: Path):
    manager, store, source_state = _build_state(tmp_path)
    export_day(manager, store.db_path, tmp_path / "ev", date(2026, 10, 1), None, source_state)
    (summary,) = _read(tmp_path / "ev" / "daily_summary.csv")
    assert (summary["raw_alerts"], summary["meta_alerts"], summary["arr"]) == ("0", "0", "")


def test_evidence_endpoint_requires_auth_and_allowlist(tmp_path: Path):
    manager, store, source_state = _build_state(tmp_path)
    export_day(manager, store.db_path, tmp_path / "ev", DAY, None, source_state)
    app = create_app(api_key="k")
    app.state.evidence_dir = tmp_path / "ev"
    client = TestClient(app)
    assert client.get("/api/v1/evidence/daily_summary.csv").status_code == 401
    ok = client.get("/api/v1/evidence/daily_summary.csv", headers={"Authorization": "Bearer k"})
    assert ok.status_code == 200 and ok.text.startswith("date,model_version")
    assert client.get("/api/v1/evidence/state.json", headers={"Authorization": "Bearer k"}).status_code == 404
    assert client.get("/api/v1/evidence/..%2Fstate.json", headers={"Authorization": "Bearer k"}).status_code == 404


def test_daily_job_schedule_and_catch_up():
    ran = []
    now = datetime(2026, 10, 17, 9, 0, tzinfo=WITA)
    job = DailyJob("t", ran.append, time(0, 5), is_done=lambda d: False, now_fn=lambda: now)
    assert job.seconds_until_next() == (timedelta(hours=15, minutes=5)).total_seconds()
    job.start()
    job.stop()
    assert ran == [date(2026, 10, 16)]  # catch-up kemarin karena 00:05 sudah lewat


def test_cli_exports_from_durable_state(tmp_path: Path):
    import subprocess
    import sys

    manager, store, _ = _build_state(tmp_path)
    repo = Path(__file__).resolve().parents[3]
    out = subprocess.run(
        [sys.executable, str(repo / "scripts" / "export_live_evidence.py"), "--state-file", str(manager.filepath),
         "--evidence-db", str(store.db_path), "--date", "2026-10-16"],
        capture_output=True, text=True, check=True,
    )
    assert json.loads(out.stdout)["raw_alerts"] == 4
    assert (tmp_path / "evidence" / "daily_summary.csv").exists()
