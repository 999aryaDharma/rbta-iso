"""Test batas tanggung jawab paket API."""
from pathlib import Path

API_SRC = Path(__file__).resolve().parent.parent.parent.parent / "src" / "api"


def test_no_research_logic_in_api_adapters():
    """Adapter Shuffle dan formatter Telegram tidak boleh berisi logika algoritma/model."""
    forbidden = [
        "IsolationForest",
        "RobustScaler",
        "AgentTemporalState",
        "calculate_baseline",
        "compute_tukey_threshold",
    ]

    for filename in ["shuffle_adapter.py", "telegram_formatter.py"]:
        file_path = API_SRC / filename
        if file_path.exists():
            content = file_path.read_text(encoding="utf-8")
            for f in forbidden:
                assert f not in content, f"Forbidden logic symbol '{f}' found in {filename}"


def test_authentication_uses_constant_time_secret_comparison():
    auth_source = (API_SRC / "auth.py").read_text(encoding="utf-8")
    app_source = (API_SRC / "app.py").read_text(encoding="utf-8")
    assert "compare_digest" in auth_source
    assert "compare_digest" in app_source
