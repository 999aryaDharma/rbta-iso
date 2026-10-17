"""T8: label analyst, antrean review deterministik, dan ekspor analyst_verdicts.csv."""

import csv
from datetime import date, datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3

from fastapi.testclient import TestClient

from src.api.app import create_app
from src.runtime.evidence_export import export_analyst_verdicts
from src.runtime.review_queue import build_review_queue, sample_ids
from tests.unit.runtime.test_live_coordinator import create_test_service

DAY = date(2026, 10, 16)
T0 = datetime(2026, 10, 15, 17, 0, tzinfo=timezone.utc)  # 16 Okt 01:00 WITA
AUTH = {"Authorization": "Bearer k"}


def _seed(service, n_suppress=40, n_digest=20, n_escalate=3):
    rows, meta_id = [], 1
    for action, decision, n in (("SUPPRESS", "NOISE", n_suppress), ("DAILY_DIGEST", "NOISE_HIGH", n_digest),
                                ("ESCALATE", "CRITICAL", n_escalate)):
        for _ in range(n):
            end = T0 + timedelta(minutes=meta_id)
            rows.append((meta_id, json.dumps({
                "meta_id": meta_id, "agent_id": "001", "agent_name": "web-1", "rule_group_primary": "pam",
                "start_time": end.isoformat(), "end_time": end.isoformat(), "alert_count": 1, "max_severity": 5,
                "anomaly_score": 0.5, "threshold_used": 0.8, "decision": decision, "action": action,
                "escalate": action == "ESCALATE", "model_version": "m", "seven_features": {},
            })))
            meta_id += 1
    with sqlite3.connect(service.state_manager.history_db_path) as conn:
        conn.executemany("INSERT INTO finalized_history (meta_id, scored_data) VALUES (?, ?)", rows)


def _client(tmp_path: Path):
    service = create_test_service(tmp_path)
    _seed(service)
    return service, TestClient(create_app(service=service, api_key="k"))


def test_sample_is_deterministic_and_five_percent():
    ids = list(range(100, 141))  # 41 -> ceil(2.05) = 3
    first = sample_ids(ids, DAY, "SUPPRESS")
    assert first == sample_ids(list(reversed(ids)), DAY, "SUPPRESS")
    assert len(first) == 3 and set(first) <= set(ids)
    assert sample_ids(ids, DAY + timedelta(days=1), "SUPPRESS") != first or len(ids) <= 3
    assert sample_ids([], DAY, "SUPPRESS") == []


def test_review_queue_contains_all_escalate_and_samples(tmp_path: Path):
    service, client = _client(tmp_path)
    body = client.get("/api/v1/meta-alerts/review-queue", params={"end_date": "2026-10-16", "days": 1},
                      headers=AUTH).json()
    reasons = [i["queue_reason"] for i in body["items"]]
    assert reasons.count("ESCALATE") == 3
    assert reasons.count("SAMPLE_SUPPRESS") == 2  # ceil(5% x 40)
    assert reasons.count("SAMPLE_DIGEST") == 1  # ceil(5% x 20)
    assert body["items"] == build_review_queue(service.state_manager, [DAY])
    assert body["summary"][0]["escalate_in_queue"] == 3
    assert body["summary"][0]["precision_incident_at_escalate"] is None


def test_verdict_roundtrip_validation_and_detail(tmp_path: Path):
    service, client = _client(tmp_path)
    esc_ids = [61, 62, 63]
    ok = client.post(f"/api/v1/meta-alerts/{esc_ids[0]}/verdict",
                     json={"verdict": "incident", "note": " brute force ", "labeled_by": "arya"}, headers=AUTH)
    assert ok.status_code == 200 and ok.json()["note"] == "brute force"
    client.post(f"/api/v1/meta-alerts/{esc_ids[1]}/verdict", json={"verdict": "noise"}, headers=AUTH)
    assert client.post("/api/v1/meta-alerts/61/verdict", json={"verdict": "attack"}, headers=AUTH).status_code == 422
    assert client.post("/api/v1/meta-alerts/9999/verdict", json={"verdict": "noise"}, headers=AUTH).status_code == 404
    assert client.post("/api/v1/meta-alerts/61/verdict", json={"verdict": "noise"}).status_code == 401

    detail = client.get("/api/v1/meta-alerts/61", headers=AUTH).json()
    assert detail["analyst_verdict"]["verdict"] == "incident"
    assert detail["decision"] == "CRITICAL" and detail["action"] == "ESCALATE"  # label tidak mengubah model

    summary = client.get("/api/v1/meta-alerts/review-queue", params={"end_date": "2026-10-16", "days": 1},
                         headers=AUTH).json()["summary"][0]
    assert (summary["escalate_labeled"], summary["escalate_incident"], summary["escalate_noise"]) == (2, 1, 1)
    assert summary["precision_incident_at_escalate"] == 0.5

    out = tmp_path / "evidence"
    assert export_analyst_verdicts(service.state_manager, out) == 2
    with (out / "analyst_verdicts.csv").open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert [(r["meta_id"], r["verdict"], r["queue_reason"], r["date"]) for r in rows] == [
        ("61", "incident", "ESCALATE", "2026-10-16"), ("62", "noise", "ESCALATE", "2026-10-16"),
    ]
    with (out / "analyst_verdicts_summary.csv").open(newline="", encoding="utf-8") as f:
        (srow,) = list(csv.DictReader(f))
    assert float(srow["precision_incident_at_escalate"]) == 0.5
