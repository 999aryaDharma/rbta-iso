"""Unit test entrypoint kanonis, memastikan tidak ada import modul lama."""

import importlib
import sys
from pathlib import Path
import pytest

def test_main_imports_no_legacy():
    """main.py dan src.research.orchestrator tidak boleh meng-import dari src.engine.*."""
    import main
    import src.research.orchestrator as orchestrator

    # Modul orchestrator harus punya fungsi kanonis yang dibutuhkan.
    assert hasattr(orchestrator, "run_canonical_research_pipeline")
    assert hasattr(orchestrator, "_generate_engineering_smoke_fixture")
    assert hasattr(orchestrator, "main")
    assert hasattr(main, "main")

    # Tidak ada modul engine lama yang termuat saat import.
    new_legacy_modules = [m for m in sys.modules if m.startswith("src.engine")]
    invalid_modules = [m for m in new_legacy_modules if not m.startswith("src.rbta.engine") and m != "src.engine"]
    assert len(invalid_modules) == 0, f"Found legacy modules imported: {invalid_modules}"

def test_no_active_code_imports_legacy():
    """Tidak ada file python aktif yang meng-import dari src.engine.*."""
    repo_root = Path(__file__).parent.parent.parent
    src_dir = repo_root / "src"

    invalid_imports = []

    for py_file in src_dir.rglob("*.py"):
        if "archive" in py_file.parts:
            continue

        content = py_file.read_text(encoding="utf-8")
        lines = content.splitlines()
        for i, line in enumerate(lines):
            line = line.strip()
            if line.startswith("import src.engine") or line.startswith("from src.engine"):
                invalid_imports.append(f"{py_file.relative_to(repo_root)}:{i+1}: {line}")

    assert not invalid_imports, "Found legacy imports in active code:\n" + "\n".join(invalid_imports)


def test_src_never_imports_main():
    """Tidak ada file di src/ yang meng-import dari main.py di root."""
    repo_root = Path(__file__).parent.parent.parent
    src_dir = repo_root / "src"

    forbidden_imports = []
    for py_file in src_dir.rglob("*.py"):
        if "archive" in py_file.parts:
            continue
        content = py_file.read_text(encoding="utf-8")
        lines = content.splitlines()
        for i, line in enumerate(lines):
            line = line.strip()
            if line.startswith("import main") or line.startswith("from main import"):
                forbidden_imports.append(f"{py_file.relative_to(repo_root)}:{i+1}: {line}")

    assert not forbidden_imports, "Found forbidden imports from root main in src/:\n" + "\n".join(forbidden_imports)


def test_main_is_thin_adapter():
    """main.py di root hanya adapter tipis yang mendelegasikan ke src.research.orchestrator."""
    repo_root = Path(__file__).parent.parent.parent
    main_file = repo_root / "main.py"

    content = main_file.read_text(encoding="utf-8")
    assert "src.research.orchestrator" in content
    assert "main()" in content
    # main.py harus adapter tipis (< 30 baris).
    non_empty_lines = [l for l in content.splitlines() if l.strip()]
    assert len(non_empty_lines) <= 20, f"main.py has {len(non_empty_lines)} lines, expected <= 20"

