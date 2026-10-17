"""Unit test BatchResearchRunner."""
from datetime import datetime, timedelta, timezone
import pytest
import pandas as pd

from src.contracts.raw_alert import CanonicalRawAlert
from src.features.extractor import FEATURE_COLUMNS
from src.model.scoring_pipeline import ScoringPipeline, train_reference_pipeline
from src.runners.batch_runner import BatchResearchRunner


def make_alert(idx: int, ts: datetime, group: str = "pam", level: int = 3, agent_idx: int = 1, mitre: tuple[str, ...] = ()) -> CanonicalRawAlert:
    return CanonicalRawAlert(
        wazuh_alert_id=f"alert_{idx}",
        timestamp=ts,
        agent_id=f"agent_{agent_idx}",
        agent_name=f"soc-{agent_idx}",
        rule_group_primary=group,
        rule_level=level,
        rule_id=f"550{idx % 5}",
        mitre_tactics=mitre,
        srcip=None,
        agent_criticality=agent_idx,
    )


def test_batch_runner_aggregates_and_extracts_features():
    """Batch runner memproses aliran menjadi MetaAlert dan mengekstrak DataFrame 7 fitur kanonis."""
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    alerts = [make_alert(i, base_t + timedelta(minutes=i)) for i in range(10)]

    runner = BatchResearchRunner(base_delta_t=timedelta(minutes=15), adaptive=False)
    result = runner.run(alerts)

    assert len(result.meta_alerts) == 1
    assert result.meta_alerts[0].alert_count == 10
    assert isinstance(result.features_df, pd.DataFrame)
    assert list(result.features_df.columns) == list(FEATURE_COLUMNS)
    assert len(result.features_df) == 1
    assert result.scored_meta_alerts is None


def test_batch_runner_with_scoring_pipeline():
    """Batch runner dengan scoring pipeline menghasilkan meta-alert terskor."""
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    # Bangkitkan 40 alert dengan level, agent, dan taktik MITRE yang bervariasi.
    alerts = [
        make_alert(
            i,
            base_t + timedelta(minutes=i * 20),
            level=(i % 12) + 1,
            agent_idx=(i % 4) + 1,
            mitre=("Execution",) if i % 3 == 0 else (),
        )
        for i in range(40)
    ]

    # Jalankan batch tanpa scoring untuk mendapatkan meta training.
    runner = BatchResearchRunner(base_delta_t=timedelta(minutes=15), adaptive=False)
    unscored_result = runner.run(alerts)
    assert len(unscored_result.meta_alerts) == 40

    # Latih bundle model.
    bundle = train_reference_pipeline(unscored_result.meta_alerts, random_state=42, model_version="batch-v1")
    scoring_pipe = ScoringPipeline(bundle)

    # Jalankan batch dengan scoring.
    scored_runner = BatchResearchRunner(
        base_delta_t=timedelta(minutes=15),
        adaptive=False,
        scoring_pipeline=scoring_pipe,
    )
    scored_result = scored_runner.run(alerts)

    assert scored_result.scored_meta_alerts is not None
    assert len(scored_result.scored_meta_alerts) == 40
    assert scored_result.scored_df is not None
    assert len(scored_result.scored_df) == 40
