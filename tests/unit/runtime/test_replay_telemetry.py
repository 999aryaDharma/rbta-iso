"""Unit test telemetri pipeline ReplayController, ring buffer trace, dan integrasi Telegram tertunda."""

import json
from pathlib import Path
import pytest

from src.contracts.meta_alert import MetaAlert
from src.contracts.raw_alert import CanonicalRawAlert
from src.model.scoring_pipeline import train_reference_pipeline
from src.runtime.replay_controller import ReplayController


def _create_sample_dataset(dataset_path: Path, count: int = 15):
    """Bangkitkan file JSONL alert Wazuh contoh untuk test."""
    records = []
    for i in range(count):
        records.append({
            "timestamp": f"2026-08-29T10:{i:02d}:00.000Z",
            "agent": {"id": "001", "name": "prod-wazuh-agent"},
            "rule": {
                "id": str(5710 + (i % 3)),
                "level": 7 if i < 10 else 12,
                "description": f"Test alert {i}",
                "groups": ["authentication_failed" if i < 10 else "web_attack", "sshd"],
                "mitre": {"tactic": ["initial-access"] if i < 10 else ["initial-access", "credential-access"]},
            },
            "data": {"srcip": "192.168.1.100"},
            "location": "/var/log/auth.log",
            "id": f"test-alert-{i:03d}",
        })
    with open(dataset_path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


@pytest.fixture
def trained_pipeline():
    """Buat scoring pipeline terlatih yang minimal untuk test."""
    from datetime import datetime, timezone
    sample_metas = [
        MetaAlert(
            meta_id=i,
            agent_id="001",
            agent_name="agent-1",
            rule_group_primary="authentication_failed",
            start_time=datetime(2026, 8, 29, 10, i, 0, tzinfo=timezone.utc),
            end_time=datetime(2026, 8, 29, 10, i, 30, tzinfo=timezone.utc),
            alert_count=5 + i,
            max_severity=3 + (i % 8),
            rule_id_distribution={"5710": 5 + i},
            severity_distribution={3: 5 + i},
            mitre_tactics_unique=("initial-access",),
            critical_mitre_present=False,
            agent_criticality=1,
            wazuh_alert_ids=(f"alt-{i}",),
        )
        for i in range(1, 10)
    ]
    bundle = train_reference_pipeline(sample_metas, model_version="rbta-if-v1")
    from src.model.scoring_pipeline import ScoringPipeline
    return ScoringPipeline(bundle)


def test_replay_telemetry_structure_and_trace(tmp_path: Path, trained_pipeline):
    data_dir = tmp_path / "data"
    runs_dir = tmp_path / "runs"
    data_dir.mkdir()
    runs_dir.mkdir()

    ds_path = data_dir / "telemetry_sample.jsonl"
    _create_sample_dataset(ds_path, count=20)

    controller = ReplayController(
        scoring_pipeline=trained_pipeline,
        replay_data_dir=data_dir,
        replay_runs_dir=runs_dir,
    )

    # State awal dengan telemetri kosong.
    init_status = controller.get_status()
    assert "telemetry" in init_status
    telemetry = init_status["telemetry"]
    assert telemetry["raw"]["processed"] == 0
    assert telemetry["decision_counts"]["ESCALATE"] == 0
    assert isinstance(telemetry["trace"], list)

    # Mulai replay dan tunggu sampai selesai.
    controller.start(dataset_name="telemetry_sample.jsonl", speed_factor="MAX")
    
    # Tunggu thread selesai.
    if controller._thread:
        controller._thread.join(timeout=10.0)

    final_status = controller.get_status()
    assert final_status["status"] == "COMPLETED"
    assert final_status["processed_count"] == 20

    final_telemetry = final_status["telemetry"]
    assert final_telemetry["raw"]["processed"] == 20
    assert final_telemetry["raw"]["evidence_count"] == 20
    assert final_telemetry["raw"]["last_alert"] is not None
    assert final_telemetry["rbta"]["finalized_meta_alerts"] > 0
    live_eval = final_telemetry["evaluation_live"]
    assert live_eval["raw_alerts"] == 20
    assert live_eval["active_meta_alerts"] == 0
    assert live_eval["finalized_meta_alerts"] == final_telemetry["rbta"]["finalized_meta_alerts"]
    assert live_eval["model_provenance"]["model_version"] == "rbta-if-v1"
    assert live_eval["claim_boundary"]["accuracy_available"] is False

    # Jumlah per decision sama dengan jumlah yang difinalkan.
    dec_counts = final_telemetry["decision_counts"]
    total_decisions = sum(dec_counts.values())
    assert total_decisions == final_telemetry["rbta"]["finalized_meta_alerts"]

    # Ring buffer trace berisi operasi.
    trace = final_telemetry["trace"]
    assert len(trace) > 0
    stages = {item["stage"] for item in trace}
    assert "RAW" in stages or "FINALIZE" in stages or "DECISION" in stages

    # latest_meta_alert punya tepat 7 fitur beserta skornya.
    latest_meta = final_telemetry["latest_meta_alert"]
    if latest_meta:
        assert "seven_features" in latest_meta
        assert "anomaly_score" in latest_meta
        assert "threshold_used" in latest_meta
        assert "decision" in latest_meta
        assert "action" in latest_meta

    # Cek endpoint payload Telegram.
    payloads_dto = controller.get_telegram_payloads(limit=10)
    assert "items" in payloads_dto
    assert "total_count" in payloads_dto
    assert payloads_dto["total_count"] == dec_counts["ESCALATE"]

    evaluation_started = controller.start_evaluation(random_seed=42)
    assert evaluation_started["status"] in {"RUNNING", "COMPLETED"}
    evaluation = controller.wait_until_evaluation_complete(timeout=15.0)
    assert evaluation["status"] == "COMPLETED"
    assert evaluation["artifact_available"] is True
    assert controller.get_evaluation_artifact_path().is_file()
