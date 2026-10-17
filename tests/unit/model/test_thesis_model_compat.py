"""T2: runtime memuat model thesis tanpa InconsistentVersionWarning dan skornya identik dengan run skripsi."""

import warnings

import numpy as np
import pandas as pd
import pytest
import sklearn

from src.features.extractor import FEATURE_COLUMNS
from src.model.decision import evaluate_decision
from tests.thesis_artifacts import (
    THESIS_MODEL_VERSION,
    THESIS_SCORED_CSV,
    THESIS_THRESHOLD,
    require_thesis_model,
)


def test_runtime_sklearn_matches_training_version():
    assert sklearn.__version__ == "1.7.2"


def test_thesis_bundle_loads_without_inconsistent_version_warning():
    from sklearn.exceptions import InconsistentVersionWarning

    with warnings.catch_warnings():
        warnings.simplefilter("error", InconsistentVersionWarning)
        bundle = require_thesis_model()
    assert bundle.metadata["model_version"] == THESIS_MODEL_VERSION
    assert bundle.metadata["sklearn_version"] == sklearn.__version__
    assert bundle.threshold.threshold == THESIS_THRESHOLD


def test_thesis_scores_reproduce_published_rows():
    bundle = require_thesis_model()
    df = pd.read_csv(THESIS_SCORED_CSV)
    # Sampel deterministik: tiap 500 baris + semua baris ESCALATE (kelas paling langka).
    sample = pd.concat([df.iloc[::500], df[df["action"] == "ESCALATE"]]).drop_duplicates("meta_id")
    assert len(sample) > 40

    raw = -bundle.model.score_samples(bundle.scaler.transform(sample[list(FEATURE_COLUMNS)]))
    np.testing.assert_allclose(raw, sample["raw_model_score"].to_numpy(), rtol=0, atol=1e-9)

    for raw_score, row in zip(raw, sample.itertuples(index=False)):
        anomaly = bundle.calibration.calibrate(float(raw_score))
        assert anomaly == pytest.approx(row.anomaly_score, abs=1e-9)
        decision, action, _ = evaluate_decision(
            anomaly_score=anomaly,
            threshold=bundle.threshold.threshold,
            max_severity=int(row.max_severity),
            alert_count=int(row.alert_count),
            mitre_tactic_count=int(row.mitre_tactic_count),
        )
        assert (decision, action) == (row.decision, row.action), row.meta_id


def test_reference_quantiles_artifact_matches_frozen_scaler():
    import json
    from pathlib import Path

    bundle = require_thesis_model()
    path = Path(__file__).resolve().parents[3] / "artifacts" / "reference_feature_quantiles.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["source"]["model_version"] == THESIS_MODEL_VERSION
    assert data["source"]["n_meta"] == bundle.metadata["training_row_count"]
    for i, feature in enumerate(FEATURE_COLUMNS):
        q = data["quantiles"][feature]
        assert q["median"] == pytest.approx(bundle.scaler.center_[i], abs=1e-12)
        iqr = q["q3"] - q["q1"]
        # RobustScaler memakai scale 1 untuk IQR nol (fitur itu diskalakan dalam satuan mentah).
        assert bundle.scaler.scale_[i] == pytest.approx(iqr if iqr > 0 else 1.0, abs=1e-12)
