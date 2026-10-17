"""Skema fitur hanya boleh didefinisikan di satu tempat."""
from pathlib import Path
import re

SRC_DIR = Path(__file__).resolve().parent.parent.parent.parent / "src"


def test_single_authoritative_feature_columns_declaration():
    """FEATURE_COLUMNS hanya boleh dideklarasikan di src/features/extractor.py."""
    pattern = re.compile(r"^FEATURE_COLUMNS\s*(:\s*[^=]+)?\s*=", re.MULTILINE)
    declarations = []

    for py_file in SRC_DIR.rglob("*.py"):
        rel_path = py_file.relative_to(SRC_DIR).as_posix()
        # Diizinkan di features/extractor.py.
        if rel_path in ("features/extractor.py", "features/__init__.py"):
            continue
        # Lewati modul engine lama.
        if rel_path in ("engine/feature_engineering.py", "engine/isolation_forest.py", "engine/rbta_core.py"):
            continue

        content = py_file.read_text(encoding="utf-8")
        if pattern.search(content):
            declarations.append(rel_path)

    assert not declarations, (
        f"Found duplicate FEATURE_COLUMNS declarations in:\n" + "\n".join(declarations)
    )
