"""Konstanta domain tidak boleh terduplikasi dan source tidak boleh berisi path workstation."""
import re
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent.parent.parent / "src"


def test_no_duplicate_authoritative_domain_declarations():
    """Konstanta domain hanya boleh didefinisikan di src/config/domain.py."""
    forbidden_declarations = [
        re.compile(r"^AGENT_CRITICALITY\s*(:\s*[^=]+)?\s*=", re.MULTILINE),
        re.compile(r"^GROUP_SEVERITY_WEIGHT\s*(:\s*[^=]+)?\s*=", re.MULTILINE),
        re.compile(r"^CRITICAL_MITRE_TACTICS\s*(:\s*[^=]+)?\s*=", re.MULTILINE),
    ]

    duplicates = []
    for py_file in SRC_DIR.rglob("*.py"):
        rel_path = py_file.relative_to(SRC_DIR).as_posix()
        # Hanya boleh di config/domain.py.
        if rel_path == "config/domain.py":
            continue

        content = py_file.read_text(encoding="utf-8")
        for pattern in forbidden_declarations:
            matches = pattern.findall(content)
            if matches:
                duplicates.append(f"{rel_path}: matches {pattern.pattern}")

    assert not duplicates, (
        f"Found duplicate authoritative domain constant declarations in:\n"
        + "\n".join(duplicates)
        + "\nAll domain constants MUST be imported from src.config.domain."
    )


def test_no_workstation_specific_absolute_paths():
    """Source code aktif tidak boleh berisi path absolut workstation (mis. drive D:/C:, /home/, /Users/)."""
    # Mencocokkan pola drive Windows (D:, C:) atau /home/ dan /Users/.
    forbidden_path_pattern = re.compile(r'["\'](?:[a-zA-Z]:[\\/]|/(?:home|Users)/)[^"\']*["\']')

    found_paths = []
    for py_file in SRC_DIR.rglob("*.py"):
        rel_path = py_file.relative_to(SRC_DIR).as_posix()
        content = py_file.read_text(encoding="utf-8")
        matches = forbidden_path_pattern.findall(content)
        if matches:
            found_paths.append(f"{rel_path}: {matches}")

    assert not found_paths, (
        "Found hardcoded workstation absolute paths in source code:\n"
        + "\n".join(found_paths)
        + "\nAll paths must be relative or passed via configuration."
    )
