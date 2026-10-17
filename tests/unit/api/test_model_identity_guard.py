"""T1: guard identitas model (RBTA_EXPECTED_MODEL_SHA256) dan pemisahan /ready vs status ber-auth."""

import hashlib
from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from src.api.server import create_production_app
from src.deploy.runtime_validation import RuntimeValidationError, validate_model_artifacts
from tests.unit.api.test_server_bootstrap import publish_test_model

API_KEY = "identity-test-key"


def _env(tmp_path: Path, **extra: str) -> dict:
    env = {
        "RBTA_MODEL_REGISTRY_DIR": str(tmp_path / "models"),
        "RBTA_MODEL_VERSION": "ident-v1",
        "RBTA_STATE_FILE": str(tmp_path / "runtime" / "state.json"),
        "RBTA_API_KEY": API_KEY,
    }
    env.update(extra)
    return env


def _sha(tmp_path: Path) -> str:
    return hashlib.sha256((tmp_path / "models" / "ident-v1" / "isolation_forest.joblib").read_bytes()).hexdigest()


def test_matching_hash_starts_and_status_exposes_identity(tmp_path: Path):
    publish_test_model(tmp_path / "models", "ident-v1")
    sha = _sha(tmp_path)
    client = TestClient(create_production_app(env=_env(tmp_path, RBTA_EXPECTED_MODEL_SHA256=sha.upper())))

    ready = client.get("/ready")
    assert ready.status_code == 200
    assert ready.json() == {"ready": True, "active_model_version": "ident-v1"}

    status = client.get("/api/v1/live/status", headers={"Authorization": f"Bearer {API_KEY}"}).json()
    assert status["model"]["version"] == "ident-v1"
    assert status["model"]["sha256"] == sha
    assert isinstance(status["model"]["threshold"], float)
    assert isinstance(status["model"]["q3"], float)


def test_mismatching_hash_refuses_to_start(tmp_path: Path):
    publish_test_model(tmp_path / "models", "ident-v1")
    with pytest.raises(RuntimeValidationError, match="Model identity mismatch"):
        create_production_app(env=_env(tmp_path, RBTA_EXPECTED_MODEL_SHA256="0" * 64))


def test_expected_hash_without_model_refuses_to_start(tmp_path: Path):
    (tmp_path / "models").mkdir()
    with pytest.raises(RuntimeValidationError, match="no active model bundle"):
        create_production_app(env=_env(tmp_path, RBTA_EXPECTED_MODEL_SHA256="0" * 64))


def test_ready_never_leaks_threshold_without_expected_hash(tmp_path: Path):
    publish_test_model(tmp_path / "models", "ident-v1")
    body = TestClient(create_production_app(env=_env(tmp_path))).get("/ready").json()
    assert set(body) == {"ready", "active_model_version"}
    assert "threshold" not in str(body)


def test_runtime_validation_checks_expected_hash(tmp_path: Path):
    publish_test_model(tmp_path / "models", "ident-v1")
    info = validate_model_artifacts(tmp_path / "models", "ident-v1", expected_sha256=_sha(tmp_path))
    assert info["model_sha256"] == _sha(tmp_path)
    with pytest.raises(RuntimeValidationError, match="Model identity mismatch"):
        validate_model_artifacts(tmp_path / "models", "ident-v1", expected_sha256="f" * 64)


@pytest.mark.parametrize("raw, expected_sec", [(None, 900.0), ("", 900.0), ("10", 600.0)])
def test_base_delta_t_env_is_opt_in(tmp_path: Path, raw, expected_sec):
    publish_test_model(tmp_path / "models", "ident-v1")
    extra = {} if raw is None else {"RBTA_BASE_DELTA_T_MIN": raw}
    client = TestClient(create_production_app(env=_env(tmp_path, **extra)))
    status = client.get("/api/v1/live/status", headers={"Authorization": f"Bearer {API_KEY}"}).json()
    assert status["base_delta_t_sec"] == expected_sec


@pytest.mark.parametrize("raw", ["abc", "0", "-5"])
def test_base_delta_t_env_rejects_invalid(tmp_path: Path, raw):
    publish_test_model(tmp_path / "models", "ident-v1")
    with pytest.raises(ValueError, match="RBTA_BASE_DELTA_T_MIN"):
        create_production_app(env=_env(tmp_path, RBTA_BASE_DELTA_T_MIN=raw))
