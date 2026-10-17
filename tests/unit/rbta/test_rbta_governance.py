"""Test batas arsitektur inti RBTA."""
from pathlib import Path
import re
from src.rbta.engine import RBTAEngine

RBTA_SRC_DIR = Path(__file__).resolve().parent.parent.parent.parent / "src" / "rbta"


def test_rbta_src_contains_no_forbidden_legacy_symbols():
    """src/rbta/ tidak boleh meng-import atau mendeklarasikan konstruksi lama yang dilarang."""
    forbidden_tokens = [
        "HIGH_FREQ",
        "LOW_FREQ",
        "SHRINK_RATE",
        "EXPAND_RATE",
        "late_drop",
        "CompoundMetaAlert",
        "ground_truth",
        "is_synthetic",
        "IsolationForest",
        "RobustScaler",
    ]

    violations = []
    for py_file in RBTA_SRC_DIR.rglob("*.py"):
        rel_path = py_file.relative_to(RBTA_SRC_DIR).as_posix()
        content = py_file.read_text(encoding="utf-8")
        for token in forbidden_tokens:
            if re.search(rf"\b{re.escape(token)}\b", content):
                violations.append(f"{rel_path}: matches '{token}'")

    assert not violations, (
        f"Found forbidden legacy tokens in src/rbta/:\n" + "\n".join(violations)
    )


def test_engine_instances_do_not_share_mutable_state():
    """Instance RBTAEngine yang terpisah harus punya state internal yang benar-benar terisolasi."""
    engine1 = RBTAEngine()
    engine2 = RBTAEngine()

    assert engine1._temporal_states is not engine2._temporal_states
    assert engine1._active_buckets is not engine2._active_buckets
    assert engine1._seen_alert_ids is not engine2._seen_alert_ids
