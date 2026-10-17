"""T11: top_deviations aditif; skor, decision, action identik dengan sebelum perubahan."""

from datetime import datetime, timezone
import json
from pathlib import Path

import numpy as np
import pytest

from src.contracts.scored_meta_alert import ScoredMetaAlert
from src.features.extractor import FEATURE_COLUMNS, SevenFeatureExtractor
from src.model.scoring_pipeline import ScoringPipeline, top_scaled_deviations
from src.runtime.service import _serialize_scored_alert
from src.runtime.telegram_formatter import format_telegram_alert
from tests.integration.test_live_offline_parity import THESIS_DELTA_T, load_fixture_alerts, run_live, run_offline
from tests.thesis_artifacts import require_thesis_model

GOLDEN = Path(__file__).resolve().parents[1] / "fixtures" / "parity_scores_golden.json"


@pytest.fixture(scope="module")
def pipeline():
    return ScoringPipeline(require_thesis_model())


def test_scores_identical_to_pre_t11_golden(pipeline, tmp_path: Path):
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))["rows"]
    alerts = load_fixture_alerts()
    for scored in (run_offline(pipeline, alerts), run_live(pipeline, alerts, tmp_path)):
        assert [[s.meta_id, s.raw_model_score, s.anomaly_score, s.decision, s.action] for s in scored] == golden


def test_top_deviations_are_largest_scaled_features(pipeline):
    from src.runners.batch_runner import BatchResearchRunner

    metas = BatchResearchRunner(base_delta_t=THESIS_DELTA_T, adaptive=True).run(load_fixture_alerts()).meta_alerts
    batch = pipeline.score_batch(metas)
    for meta, scored in zip(metas, batch):
        x = pipeline.scaler.transform(SevenFeatureExtractor.extract_features_df([meta]))[0]
        expected = sorted(range(7), key=lambda j: (-abs(x[j]), j))[:2]
        assert [n for n, _ in scored.top_deviations] == [FEATURE_COLUMNS[j] for j in expected]
        assert [v for _, v in scored.top_deviations] == pytest.approx([x[j] for j in expected], abs=1e-12)
        single = pipeline.score_single(meta).top_deviations
        assert [n for n, _ in single] == [n for n, _ in scored.top_deviations]
        assert [v for _, v in single] == pytest.approx([v for _, v in scored.top_deviations], abs=1e-12)


def test_tie_break_is_feature_order():
    assert top_scaled_deviations(np.array([0, 2.0, -2.0, 0, 0, 0, 0])) == (
        ("mitre_tactic_count", 2.0), ("critical_mitre_tactic_present", -2.0),
    )


def _scored(**extra):
    t = datetime(2026, 10, 17, tzinfo=timezone.utc)
    return ScoredMetaAlert(1, "001", "web-1", "web", t, t, 3, 9, (), {}, 0.6, 0.9, 0.87, "CRITICAL", "ESCALATE",
                           True, "rbta-if-thesis-v1", "1.0", "minmax-v1", (), **extra)


def test_serialization_is_backward_compatible():
    from src.runtime.service import LiveRBTAService

    legacy = _serialize_scored_alert(_scored())
    assert legacy["top_deviations"] is None
    legacy.pop("top_deviations")
    parse = LiveRBTAService._parse_scored_alert
    assert parse(None, legacy).top_deviations is None  # record lama tanpa key
    new = _serialize_scored_alert(_scored(top_deviations=(("mitre_tactic_count", 4.0), ("max_severity", 2.1))))
    assert parse(None, json.loads(json.dumps(new))).top_deviations == (("mitre_tactic_count", 4.0), ("max_severity", 2.1))


def test_telegram_shows_cause_line_only_when_available():
    text = format_telegram_alert(_scored(top_deviations=(("mitre_tactic_count", 4.0), ("rule_diversity_shannon", 2.1))))
    assert "Penyebab (deviasi robust dari median reference): mitre_tactic_count +4.0, rule_diversity_shannon +2.1" in text
    assert "Penyebab" not in format_telegram_alert(_scored())
