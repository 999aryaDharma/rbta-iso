"""Test batas tanggung jawab paket runner."""
from pathlib import Path
import re

RUNNERS_SRC = Path(__file__).resolve().parent.parent.parent.parent / "src" / "runners"


def test_no_model_fitting_in_replay_runner():
    """ReplayStreamRunner tidak boleh memanggil fit atau train."""
    replay_file = RUNNERS_SRC / "replay_runner.py"
    if replay_file.exists():
        content = replay_file.read_text(encoding="utf-8")
        assert "fit(" not in content
        assert "fit_transform(" not in content
        assert "train_reference_pipeline(" not in content


def test_shared_core_usage_in_runners():
    """Batch runner dan replay runner harus meng-import dan memakai RBTAEngine serta SevenFeatureExtractor kanonis."""
    for py_file in RUNNERS_SRC.glob("*.py"):
        if py_file.name in ("__init__.py", "clock.py"):
            continue
        content = py_file.read_text(encoding="utf-8")
        assert "from src.rbta" in content or "RBTAEngine" in content
        assert "SevenFeatureExtractor" in content or "src.features" in content or "src.model" in content
