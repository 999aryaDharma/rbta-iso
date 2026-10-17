"""Test batas tanggung jawab paket evaluasi."""
from pathlib import Path

EVAL_SRC = Path(__file__).resolve().parent.parent.parent.parent / "src" / "evaluation"


def test_no_synthetic_attack_or_ground_truth_labels_in_eval_src():
    """src/evaluation tidak boleh memakai parameter atau membutuhkan ground truth / label serangan sintetis."""
    forbidden = [
        "synthetic_attack",
        "ground_truth_labels",
        "scenario_a",
        "scenario_b",
        "scenario_c",
        "pr_auc",
        "f1_score",
        "f0_5_score",
    ]
    for py_file in EVAL_SRC.glob("*.py"):
        content = py_file.read_text(encoding="utf-8").lower()
        for f in forbidden:
            assert f not in content, f"Forbidden legacy symbol '{f}' found in {py_file.name}"
