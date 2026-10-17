from datetime import datetime, timedelta, timezone
import json
import gzip
from pathlib import Path
import time
import pytest

from src.contracts.meta_alert import MetaAlert
from src.model.scoring_pipeline import ScoringPipeline, train_reference_pipeline
from src.runners.batch_runner import BatchResearchRunner
from src.runtime.replay_controller import ReplayController


@pytest.fixture
def test_bundle():
    base_t = datetime(2026, 8, 29, 10, 0, 0, tzinfo=timezone.utc)
    metas = [
        MetaAlert(
            meta_id=i,
            agent_id="001",
            agent_name="agent-ubuntu",
            rule_group_primary="authentication_failed",
            start_time=base_t + timedelta(hours=i),
            end_time=base_t + timedelta(hours=i, minutes=10),
            alert_count=5 + i,
            max_severity=3 + (i % 10),
            rule_id_distribution={"5710": 5 + i},
            severity_distribution={3: 5 + i},
            agent_criticality=1.0,
            wazuh_alert_ids=(f"a_{i}_1", f"a_{i}_2"),
            mitre_tactics_unique=("credential-access",),
            critical_mitre_present=False,
            metadata={},
        )
        for i in range(1, 10)
    ]
    return train_reference_pipeline(metas, random_state=42, model_version="replay-v1")


def create_sample_wazuh_jsonl(file_path: Path, count: int = 20) -> None:
    base_t = datetime(2026, 8, 29, 10, 0, 0, tzinfo=timezone.utc)
    lines = []
    for i in range(count):
        ts = base_t + timedelta(minutes=i * 2)
        event = {
            "id": f"event-{i:04d}",
            "timestamp": ts.isoformat(),
            "agent": {"id": "001", "name": "ubuntu-srv"},
            "rule": {
                "id": f"571{i % 5}",
                "level": (i % 12) + 1,
                "description": f"Test alert {i}",
                "groups": ["authentication_failed", "syslog"],
                "mitre": {"tactic": ["credential-access"]},
            },
            "data": {"srcip": f"192.168.1.{100 + (i % 10)}"},
            "full_log": f"Failed password for user from 192.168.1.{100 + (i % 10)}",
        }
        lines.append(json.dumps(event))
    file_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_replay_dataset_discovery_and_path_validation(tmp_path: Path, test_bundle):
    data_dir = tmp_path / "datasets"
    runs_dir = tmp_path / "runs"
    data_dir.mkdir()

    create_sample_wazuh_jsonl(data_dir / "valid1.jsonl", 5)
    create_sample_wazuh_jsonl(data_dir / "valid2.jsonl", 10)
    (data_dir / "ignore.txt").write_text("not jsonl", encoding="utf-8")

    controller = ReplayController(
        scoring_pipeline=ScoringPipeline(test_bundle),
        replay_data_dir=data_dir,
        replay_runs_dir=runs_dir,
    )

    datasets = controller.list_datasets()
    assert len(datasets) == 2
    assert datasets[0]["name"] == "valid1.jsonl"
    assert datasets[1]["name"] == "valid2.jsonl"
    assert all(item["inspection_status"] == "pending" for item in datasets)

    # Path valid.
    assert controller.validate_dataset_path("valid1.jsonl").name == "valid1.jsonl"

    # Percobaan path traversal harus gagal.
    with pytest.raises(ValueError, match="Path traversal"):
        controller.validate_dataset_path("../outside.jsonl")

    with pytest.raises(ValueError, match="Path traversal"):
        controller.validate_dataset_path("sub/nested.jsonl")

    with pytest.raises(ValueError, match=".jsonl"):
        controller.validate_dataset_path("ignore.txt")


def test_replay_malformed_json_fails_run_closed(tmp_path: Path, test_bundle):
    data_dir = tmp_path / "datasets"
    runs_dir = tmp_path / "runs"
    data_dir.mkdir()

    bad_file = data_dir / "bad.jsonl"
    bad_file.write_text("{\"id\": \"1\", \"timestamp\": \"2026-08-29T10:00:00Z\", \"agent\": {\"id\": \"001\"}, \"rule\": {\"id\": \"1\", \"level\": 3, \"groups\": [\"syslog\"]}}\nNOT_JSON\n", encoding="utf-8")

    controller = ReplayController(
        scoring_pipeline=ScoringPipeline(test_bundle),
        replay_data_dir=data_dir,
        replay_runs_dir=runs_dir,
    )

    controller.start("bad.jsonl", speed_factor="MAX")
    time.sleep(0.3)

    status = controller.get_status()
    assert status["status"] == "ERROR"
    assert status["last_error"] is not None
    assert status["last_error"]["line_number"] == 2
    assert "Malformed JSON" in status["last_error"]["error_message"]


def test_replay_naive_timestamp_fails_canonicalization(tmp_path: Path, test_bundle):
    data_dir = tmp_path / "datasets"
    runs_dir = tmp_path / "runs"
    data_dir.mkdir()

    naive_file = data_dir / "naive.jsonl"
    # Timestamp ini tanpa offset timezone -> naive.
    naive_file.write_text("{\"id\": \"1\", \"timestamp\": \"2026-08-29T10:00:00\", \"agent\": {\"id\": \"001\"}, \"rule\": {\"id\": \"1\", \"level\": 3, \"groups\": [\"syslog\"]}}\n", encoding="utf-8")

    controller = ReplayController(
        scoring_pipeline=ScoringPipeline(test_bundle),
        replay_data_dir=data_dir,
        replay_runs_dir=runs_dir,
    )

    controller.start("naive.jsonl", speed_factor="MAX")
    time.sleep(0.3)

    status = controller.get_status()
    assert status["status"] == "ERROR"
    assert status["last_error"] is not None
    assert "timezone" in status["last_error"]["error_message"].lower() or "utc" in status["last_error"]["error_message"].lower() or "iso" in status["last_error"]["error_message"].lower()


def test_replay_lifecycle_and_session_isolation(tmp_path: Path, test_bundle):
    data_dir = tmp_path / "datasets"
    runs_dir = tmp_path / "runs"
    data_dir.mkdir()

    create_sample_wazuh_jsonl(data_dir / "sample.jsonl", count=30)

    controller = ReplayController(
        scoring_pipeline=ScoringPipeline(test_bundle),
        replay_data_dir=data_dir,
        replay_runs_dir=runs_dir,
    )

    # Run 1.
    controller.start("sample.jsonl", speed_factor="MAX")
    controller.wait_until_complete(5.0)

    run1_id = controller.run_id
    assert run1_id is not None
    run1_dir = runs_dir / run1_id
    assert run1_dir.exists()
    assert (run1_dir / "state.json").exists()
    assert (run1_dir / "raw_alert_evidence.sqlite3").exists()
    assert (run1_dir / "run.json").exists()

    status = controller.get_status()
    assert status["status"] == "COMPLETED"
    assert status["processed_count"] == 30

    # Reset.
    controller.reset()
    assert controller.run_id is None
    assert controller.status == "IDLE"

    # Run 2 membuat workspace baru tanpa menimpa run 1.
    controller.start("sample.jsonl", speed_factor="MAX")
    controller.wait_until_complete(5.0)

    run2_id = controller.run_id
    assert run2_id != run1_id
    assert (runs_dir / run1_id).exists()
    assert (runs_dir / run2_id).exists()


def test_replay_pause_resume_and_stop(tmp_path: Path, test_bundle):
    data_dir = tmp_path / "datasets"
    runs_dir = tmp_path / "runs"
    data_dir.mkdir()

    create_sample_wazuh_jsonl(data_dir / "stream.jsonl", count=100)

    controller = ReplayController(
        scoring_pipeline=ScoringPipeline(test_bundle),
        replay_data_dir=data_dir,
        replay_runs_dir=runs_dir,
    )

    # Mulai dengan throttle 1x.
    controller.start("stream.jsonl", speed_factor="1")
    time.sleep(0.05)

    # Pause.
    controller.pause()
    assert controller.status == "PAUSED"
    paused_count = controller.processed_count

    time.sleep(0.1)
    # Hitungan harus tetap selama dijeda.
    assert controller.processed_count == paused_count

    # Resume.
    controller.resume()
    assert controller.status == "RUNNING"
    time.sleep(0.05)

    # Stop manual -> status harus STOPPED.
    controller.stop()
    assert controller.status == "STOPPED"
    assert controller.processed_count < 100


def test_replay_research_determinism(tmp_path: Path, test_bundle):
    data_dir = tmp_path / "datasets"
    runs_dir = tmp_path / "runs"
    data_dir.mkdir()

    create_sample_wazuh_jsonl(data_dir / "determinism.jsonl", count=50)

    controller = ReplayController(
        scoring_pipeline=ScoringPipeline(test_bundle),
        replay_data_dir=data_dir,
        replay_runs_dir=runs_dir,
    )

    # Run A.
    controller.start("determinism.jsonl", speed_factor="MAX")
    controller.wait_until_complete(5.0)
    assert controller.status == "COMPLETED"
    run_a_history = list(controller.current_service.finalized_history)
    run_a_id = controller.run_id

    controller.reset()

    # Run B.
    controller.start("determinism.jsonl", speed_factor="MAX")
    controller.wait_until_complete(5.0)
    assert controller.status == "COMPLETED"
    run_b_history = list(controller.current_service.finalized_history)
    run_b_id = controller.run_id

    assert run_a_id != run_b_id
    assert len(run_a_history) == len(run_b_history)
    assert len(run_a_history) > 0

    for a, b in zip(run_a_history, run_b_history):
        assert a.alert_count == b.alert_count
        assert a.source_alert_ids == b.source_alert_ids
        assert a.seven_features == b.seven_features
        assert abs(a.anomaly_score - b.anomaly_score) < 1e-6
        assert abs(a.threshold_used - b.threshold_used) < 1e-6
        assert a.decision == b.decision
        assert a.action == b.action


def test_replay_accepts_gzip_and_persists_frozen_dataset_manifest(tmp_path: Path, test_bundle):
    data_dir = tmp_path / "datasets"
    runs_dir = tmp_path / "runs"
    data_dir.mkdir()
    plain = data_dir / "demo.jsonl"
    create_sample_wazuh_jsonl(plain, count=12)
    compressed = data_dir / "demo.jsonl.gz"
    with plain.open("rt", encoding="utf-8") as source, gzip.open(compressed, "wt", encoding="utf-8") as target:
        target.write(source.read())
    plain.unlink()

    controller = ReplayController(
        scoring_pipeline=ScoringPipeline(test_bundle),
        replay_data_dir=data_dir,
        replay_runs_dir=runs_dir,
    )

    controller.start_catalog_refresh()
    catalog_status = controller.wait_for_catalog_refresh(timeout=5.0)
    assert catalog_status["status"] == "COMPLETED"
    listed = controller.list_datasets()
    assert listed[0]["name"] == "demo.jsonl.gz"
    assert listed[0]["total_events"] == 12
    controller.start("demo.jsonl.gz", speed_factor="MAX")
    controller.wait_until_complete(5.0)

    assert controller.status == "COMPLETED"
    run_meta = json.loads((runs_dir / controller.run_id / "run.json").read_text(encoding="utf-8"))
    assert run_meta["dataset_manifest"]["sha256"] == listed[0]["sha256"]
    assert run_meta["dataset_manifest"]["total_events"] == 12


def test_catalog_refresh_runs_in_background_and_all_requires_current_catalog(tmp_path: Path, test_bundle):
    data_dir = tmp_path / "datasets"
    runs_dir = tmp_path / "runs"
    data_dir.mkdir()
    create_sample_wazuh_jsonl(data_dir / "day-1.jsonl", count=5)
    create_sample_wazuh_jsonl(data_dir / "day-2.jsonl", count=7)
    controller = ReplayController(
        scoring_pipeline=ScoringPipeline(test_bundle),
        replay_data_dir=data_dir,
        replay_runs_dir=runs_dir,
    )

    assert controller.list_datasets()[0]["inspection_status"] == "pending"
    with pytest.raises(RuntimeError, match="Indeks dataset belum lengkap"):
        controller.start("__ALL__", speed_factor="MAX")

    started = controller.start_catalog_refresh()
    assert started["status"] in {"STARTING", "RUNNING", "COMPLETED"}
    finished = controller.wait_for_catalog_refresh(timeout=5.0)

    assert finished["status"] == "COMPLETED"
    assert finished["completed_files"] == 2
    assert finished["failed_files"] == 0
    assert finished["pending_files"] == 0
    assert all(item["inspection_status"] == "cached" for item in controller.list_datasets())
