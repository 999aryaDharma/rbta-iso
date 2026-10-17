"""Lokasi artefak run skripsi (commit 16ab574, model rbta-if-thesis-v1) untuk tes paritas.

Artefak tidak ikut git (model + CSV hasil run). Bila tidak ada, tes yang memakainya di-skip
dengan alasan yang jelas, bukan gagal.
"""

from pathlib import Path

import pytest

THESIS_RUN_DIR = Path(__file__).resolve().parents[1] / "docs" / "thesis" / "hasil-run-20261001"
THESIS_MODEL_DIR = THESIS_RUN_DIR / "model"
THESIS_SCORED_CSV = THESIS_RUN_DIR / "meta_alerts_scored.csv"
THESIS_MODEL_VERSION = "rbta-if-thesis-v1"
THESIS_THRESHOLD = 0.8724522092452893


def require_thesis_model():
    """Muat bundle thesis lewat ModelRegistry, atau skip bila artefaknya tidak tersedia."""
    if not (THESIS_MODEL_DIR / "isolation_forest.joblib").exists():
        pytest.skip(f"Artefak model thesis tidak tersedia di {THESIS_MODEL_DIR} (tidak ikut git)")
    from src.model.registry import ModelRegistry

    return ModelRegistry(base_dir=THESIS_RUN_DIR).load_bundle(THESIS_MODEL_DIR)
