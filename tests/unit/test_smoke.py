"""Smoke test fondasi proyek dan kebersihan import modul."""
import importlib
import pytest


def test_third_party_dependencies_import():
    """Semua dependency runtime dan test yang dideklarasikan bisa di-import."""
    core_modules = [
        "numpy",
        "pandas",
        "sklearn",
        "joblib",
        "matplotlib",
        "pytest",
    ]
    for mod_name in core_modules:
        mod = importlib.import_module(mod_name)
        assert mod is not None, f"Third-party module {mod_name} could not be loaded."


def test_primary_application_modules_import():
    """Modul fondasi utama bisa di-import tanpa efek samping."""
    app_modules = [
        "src.config.domain",
        "src.contracts.raw_alert",
        "src.contracts.meta_alert",
        "src.contracts.scored_meta_alert",
        "src.etl.wazuh_canonicalizer",
    ]
    for mod_name in app_modules:
        mod = importlib.import_module(mod_name)
        assert mod is not None, f"Application module {mod_name} could not be loaded."


def test_fixtures_available():
    """File fixture ada dan berisi JSON yang valid."""
    import json
    from pathlib import Path

    fixture_dir = Path(__file__).resolve().parent.parent / "fixtures" / "wazuh"
    assert fixture_dir.exists(), f"Fixture directory {fixture_dir} does not exist."

    fixture_files = [
        "raw_alert_standard.json",
        "opensearch_hit.json",
        "raw_alert_no_mitre.json",
        "raw_alert_flattened_mitre.json",
    ]
    for fname in fixture_files:
        fpath = fixture_dir / fname
        assert fpath.exists(), f"Fixture file {fname} not found."
        with open(fpath, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert isinstance(data, dict), f"Fixture {fname} did not contain a valid JSON object."
