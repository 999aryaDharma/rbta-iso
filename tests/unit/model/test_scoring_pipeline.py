"""Unit test ScoringPipeline dan reprodusibilitas inferensi per event."""
from datetime import datetime, timezone
import pytest
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

from src.contracts.meta_alert import MetaAlert
from src.contracts.scored_meta_alert import ScoredMetaAlert
from src.features.extractor import SevenFeatureExtractor
from src.model.calibration import ScoreCalibration
from src.model.scoring_pipeline import ModelArtifactBundle, ScoringPipeline, train_reference_pipeline
from src.model.threshold import TukeyThreshold


def make_meta(meta_id: int, count: int = 5, max_sev: int = 4, mitre: tuple[str, ...] = (), crit: int = 1) -> MetaAlert:
    return MetaAlert(
        meta_id=meta_id,
        agent_id="001",
        agent_name="soc-1",
        rule_group_primary="pam",
        start_time=datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc),
        end_time=datetime(2026, 8, 28, 10, 5, 0, tzinfo=timezone.utc),
        alert_count=count,
        max_severity=max_sev,
        rule_id_distribution={"5501": count},
        severity_distribution={max_sev: count},
        mitre_tactics_unique=mitre,
        critical_mitre_present=len(mitre) > 0,
        agent_criticality=crit,
        wazuh_alert_ids=(str(meta_id),),
    )


def test_train_reference_pipeline_and_bundle_attributes():
    """train_reference_pipeline melatih RobustScaler, IsolationForest (200 tree, contamination auto), kalibrasi, dan threshold."""
    # Bangkitkan 50 MetaAlert sintetis untuk reference.
    metas = [make_meta(i, count=i % 20 + 1, max_sev=i % 15, mitre=("Execution",) if i % 4 == 0 else (), crit=i % 4 + 1) for i in range(1, 51)]

    bundle = train_reference_pipeline(metas, random_state=42, model_version="test-model-v1")
    assert isinstance(bundle.scaler, RobustScaler)
    assert isinstance(bundle.model, IsolationForest)
    assert bundle.model.n_estimators == 200
    assert bundle.model.contamination == "auto"
    assert isinstance(bundle.calibration, ScoreCalibration)
    assert isinstance(bundle.threshold, TukeyThreshold)
    assert bundle.metadata["model_version"] == "test-model-v1"
    assert bundle.metadata["training_row_count"] == 50


def test_single_event_inference_parity_with_batch():
    """Skor event satu per satu lewat ScoringPipeline memberi hasil yang sama persis dengan batch."""
    metas = [make_meta(i, count=i % 10 + 1, max_sev=i % 12, crit=1) for i in range(1, 40)]
    bundle = train_reference_pipeline(metas, random_state=42, model_version="test-model-v1")
    pipeline = ScoringPipeline(bundle)

    # Skor batch.
    df_scored, batch_scored = pipeline.score_meta_alerts(metas)
    assert len(batch_scored) == len(metas)

    # Skor stream per event.
    single_scored = [pipeline.score_single(m) for m in metas]

    for b, s in zip(batch_scored, single_scored):
        assert b.meta_id == s.meta_id
        assert b.raw_model_score == pytest.approx(s.raw_model_score)
        assert b.anomaly_score == pytest.approx(s.anomaly_score)
        assert b.threshold_used == pytest.approx(s.threshold_used)
        assert b.decision == s.decision
        assert b.action == s.action
        assert b.escalate == s.escalate
        assert b.model_version == s.model_version


def test_training_and_calibration_populations_are_separate():
    """Scaler/IF di-fit pada baris reference, sementara kalibrasi dan Tukey memakai baris yang lebih belakang."""
    reference = [
        make_meta(i, count=(i % 6) + 1, max_sev=(i % 8) + 1, crit=(i % 4) + 1)
        for i in range(1, 31)
    ]
    calibration = [
        make_meta(
            100 + i,
            count=(i % 10) + 1,
            max_sev=(i % 12) + 1,
            mitre=("Execution",) if i % 3 == 0 else (),
            crit=(i % 4) + 1,
        )
        for i in range(1, 13)
    ]

    bundle = train_reference_pipeline(
        reference,
        calibration_metas=calibration,
        random_state=42,
        model_version="temporal-v1",
    )

    calibration_features = SevenFeatureExtractor.extract_features_df(calibration)
    calibration_raw = -bundle.model.score_samples(bundle.scaler.transform(calibration_features))
    assert bundle.metadata["training_row_count"] == len(reference)
    assert bundle.metadata["calibration_row_count"] == len(calibration)
    assert bundle.metadata["validation_strategy"] == "chronological_reference_calibration_test"
    assert bundle.calibration.raw_min == pytest.approx(float(calibration_raw.min()))
    assert bundle.calibration.raw_max == pytest.approx(float(calibration_raw.max()))


def test_single_event_inference_does_not_collapse():
    """Inferensi pada satu meta-alert tidak runtuh ke 0.5 atau gagal."""
    metas = [make_meta(i, count=i % 10 + 1, max_sev=i % 12) for i in range(1, 30)]
    bundle = train_reference_pipeline(metas, random_state=42, model_version="v1")
    pipeline = ScoringPipeline(bundle)

    # Satu event ekstrem.
    extreme_meta = make_meta(999, count=500, max_sev=15, mitre=("Initial Access", "Execution", "Impact"), crit=4)
    scored = pipeline.score_single(extreme_meta)

    assert isinstance(scored, ScoredMetaAlert)
    assert scored.meta_id == 999
    assert scored.anomaly_score != 0.5  # bukan fallback yang runtuh
    assert scored.seven_features["alert_count_log"] > 0
