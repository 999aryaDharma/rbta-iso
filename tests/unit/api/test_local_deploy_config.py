"""Invarian statis konfigurasi compose lokal (Windows)."""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
LOCAL_DEPLOY_DIR = REPO_ROOT / "deploy" / "local"


def test_local_compose_supports_windows_bind_and_persistent_named_state():
    compose_path = LOCAL_DEPLOY_DIR / "compose.yml"
    env_path = LOCAL_DEPLOY_DIR / ".env.example"
    assert compose_path.exists()
    assert env_path.exists()
    compose = compose_path.read_text(encoding="utf-8")
    env = env_path.read_text(encoding="utf-8")
    assert "type: bind" in compose
    assert "read_only: true" in compose
    assert "rbta-local-state" in compose
    assert "D:/KAMPUS/SKRIPSI/wazuh-data-2026/indexer-export" in env
    assert "RBTA_REPLAY_HOST_DIR" in env
    assert "RBTA_MODEL_HOST_DIR" in env
