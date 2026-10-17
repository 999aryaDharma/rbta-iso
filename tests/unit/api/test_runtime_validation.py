"""Unit test validator runtime container dan helper parsing environment."""

from datetime import datetime, timedelta, timezone
import gzip
import json
from pathlib import Path
import pytest

from src.contracts.raw_alert import CanonicalRawAlert
from src.deploy.runtime_validation import (
    RuntimeValidationError,
    run_runtime_validation,
    validate_model_artifacts,
    validate_replay_datasets,
    validate_state_directory_rw,
)
from src.model.registry import ModelRegistry
from src.model.scoring_pipeline import train_reference_pipeline
from src.runners.batch_runner import BatchResearchRunner
from scripts.deploy.read_env import parse_env_file


def _make_test_alert(i: int, ts: datetime) -> CanonicalRawAlert:
    return CanonicalRawAlert(
        wazuh_alert_id=f"art_{i}",
        timestamp=ts,
        agent_id=f"00{1 + (i % 3)}",
        agent_name=f"agent-{1 + (i % 3)}",
        rule_group_primary="pam" if i % 2 == 0 else "syslog",
        rule_level=(i % 12) + 1,
        rule_id=f"550{i % 6}",
        mitre_tactics=("credential-access",) if i % 3 == 0 else (),
        srcip=f"192.168.1.{50 + i % 10}",
        agent_criticality=(i % 3) + 1,
    )


@pytest.fixture
def test_env_fixtures(tmp_path: Path):
    # Direktori model & bundle.
    models_dir = tmp_path / "models"
    models_dir.mkdir()
    base_t = datetime(2026, 8, 29, 10, 0, 0, tzinfo=timezone.utc)
    alerts = [_make_test_alert(i, base_t + timedelta(minutes=i * 5)) for i in range(35)]
    runner = BatchResearchRunner(base_delta_t=timedelta(minutes=15), adaptive=False)
    batch_res = runner.run(alerts)
    bundle = train_reference_pipeline(batch_res.meta_alerts, random_state=42, model_version="val-model-v1")
    registry = ModelRegistry(base_dir=models_dir)
    registry.publish_bundle(bundle, model_version="val-model-v1")

    # Direktori replay & sampel jsonl.
    replay_dir = tmp_path / "replay"
    replay_dir.mkdir()
    sample_jsonl = replay_dir / "valid_dataset.jsonl"
    sample_wazuh_event = {
        "id": "wazuh-sample-001",
        "timestamp": "2026-08-29T10:15:00.000+0000",
        "agent": {"id": "001", "name": "agent-ubuntu"},
        "rule": {"id": "5501", "level": 7, "groups": ["pam"], "description": "PAM test auth"},
        "data": {"srcip": "192.168.1.100"},
    }
    sample_jsonl.write_text(json.dumps(sample_wazuh_event) + "\n", encoding="utf-8")

    # Direktori state.
    state_dir = tmp_path / "state"
    state_dir.mkdir()

    return {
        "models_dir": models_dir,
        "model_version": "val-model-v1",
        "replay_dir": replay_dir,
        "state_dir": state_dir,
    }


def test_runtime_validation_success_path(test_env_fixtures):
    """Validasi runtime lengkap lolos dengan model valid, JSONL replay valid, dan state yang bisa ditulis."""
    res = run_runtime_validation(
        models_dir=test_env_fixtures["models_dir"],
        model_version=test_env_fixtures["model_version"],
        replay_dir=test_env_fixtures["replay_dir"],
        state_dir=test_env_fixtures["state_dir"],
        strict_uid=False,  # berjalan di environment pytest
        verify_ro=False,
    )
    assert res["status"] == "PASS"
    assert res["model"]["model_version"] == "val-model-v1"
    assert res["replay"]["dataset_count"] == "1"
    assert res["replay"]["first_dataset"] == "valid_dataset.jsonl"

    # Pastikan tidak ada file probe yang tertinggal.
    probe_files = list(test_env_fixtures["state_dir"].glob("__rbta_probe_*"))
    assert len(probe_files) == 0


def test_runtime_validation_fails_on_empty_replay_dir(tmp_path: Path, test_env_fixtures):
    """Validasi runtime gagal bila direktori replay tidak berisi dataset *.jsonl."""
    empty_replay = tmp_path / "empty_replay"
    empty_replay.mkdir()

    with pytest.raises(RuntimeValidationError, match="contains zero \\*\\.jsonl datasets"):
        validate_replay_datasets(empty_replay, verify_read_only=False)


def test_runtime_validation_accepts_valid_gzip_only_replay_dir(tmp_path: Path):
    """Validasi runtime menerima format gzip yang didukung engine replay."""
    comp_replay = tmp_path / "compressed_replay"
    comp_replay.mkdir()
    payload = {
        "id": "gzip-1",
        "timestamp": "2026-08-29T10:15:00+00:00",
        "agent": {"id": "001", "name": "agent"},
        "rule": {"id": "5501", "level": 7, "groups": ["pam"]},
    }
    with gzip.open(comp_replay / "campus_batch_01.jsonl.gz", "wt", encoding="utf-8") as stream:
        stream.write(json.dumps(payload) + "\n")

    result = validate_replay_datasets(comp_replay, verify_read_only=False)
    assert result["dataset_count"] == "1"
    assert result["first_dataset"] == "campus_batch_01.jsonl.gz"


def test_runtime_validation_fails_on_corrupt_model(tmp_path: Path):
    """Validasi runtime langsung gagal bila versi model tidak ada atau bundle tidak valid."""
    empty_models = tmp_path / "empty_models"
    empty_models.mkdir()

    with pytest.raises(RuntimeValidationError, match="Model version directory not found"):
        validate_model_artifacts(empty_models, "nonexistent-v1")


def test_runtime_validation_state_rw_proof(tmp_path: Path):
    """validate_state_directory_rw menjalankan write, flush, fsync, atomic rename, read, dan delete."""
    state_dir = tmp_path / "state_test"
    validate_state_directory_rw(state_dir)
    assert state_dir.exists()
    assert len(list(state_dir.iterdir())) == 0


def test_read_env_helper_deterministic(tmp_path: Path):
    """read_env.py mem-parse KEY=VALUE, komentar, kutipan, dan whitespace dengan benar tanpa eval."""
    env_file = tmp_path / ".env.test"
    env_file.write_text(
        """
        # Leading comment
        RBTA_API_KEY="my-secret-key-123"
        RBTA_HOST_PORT=8011
        RBTA_MODEL_VERSION='prod-v1'
        RBTA_SOURCE_MODE=DEFERRED
        
        # Trailing comment
        """,
        encoding="utf-8",
    )

    env_map = parse_env_file(env_file)
    assert env_map["RBTA_API_KEY"] == "my-secret-key-123"
    assert env_map["RBTA_HOST_PORT"] == "8011"
    assert env_map["RBTA_MODEL_VERSION"] == "prod-v1"
    assert env_map["RBTA_SOURCE_MODE"] == "DEFERRED"

    # Tolak baris yang rusak.
    bad_env = tmp_path / ".env.bad"
    bad_env.write_text("THIS IS NOT A VALID LINE\n", encoding="utf-8")
    with pytest.raises(ValueError, match="missing '=' delimiter"):
        parse_env_file(bad_env)
