"""Test batas tanggung jawab paket model."""
from pathlib import Path
import re

MODEL_SRC = Path(__file__).resolve().parent.parent.parent.parent / "src" / "model"


def test_no_dynamic_contamination_or_ground_truth_in_model_src():
    """src/model tidak boleh berisi contamination dinamis atau parameter ground truth."""
    forbidden = ["compute_dynamic_contamination", "ground_truth", "is_synthetic", "scenario_id"]

    for py_file in MODEL_SRC.glob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in content, f"Found forbidden token '{token}' in {py_file.name}"


def test_no_fit_in_scoring_pipeline_inference_methods():
    """score_single dan score_meta_alerts di scoring_pipeline.py tidak boleh memanggil fit atau fit_transform."""
    pipeline_file = MODEL_SRC / "scoring_pipeline.py"
    if pipeline_file.exists():
        content = pipeline_file.read_text(encoding="utf-8")
        # score_single dan score_meta_alerts hanya boleh memakai transform.
        assert "self.scaler.transform(" in content or "scaler.transform(" in content
        assert "fit_transform" not in content
