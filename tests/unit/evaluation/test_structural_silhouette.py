"""Unit test evaluasi Silhouette struktural dan baseline permutasi."""
from datetime import datetime, timedelta, timezone
import pytest

from src.contracts.raw_alert import CanonicalRawAlert
from src.evaluation.structural_silhouette import run_structural_silhouette_evaluation
from src.model.scoring_pipeline import ScoringPipeline, train_reference_pipeline
from src.runners.batch_runner import BatchResearchRunner


def make_alert(idx: int, ts: datetime, agent_id: str = "001", group: str = "pam", level: int = 3, crit: int = 1) -> CanonicalRawAlert:
    return CanonicalRawAlert(
        wazuh_alert_id=f"alert_{idx}",
        timestamp=ts,
        agent_id=agent_id,
        agent_name=f"soc-{agent_id}",
        rule_group_primary=group,
        rule_level=level,
        rule_id=f"550{idx % 5}",
        mitre_tactics=("Execution",) if idx % 4 == 0 else (),
        srcip=None,
        agent_criticality=crit,
    )


def test_structural_silhouette_and_permutation_baseline():
    """Silhouette struktural membandingkan partisi observasi dengan 100 permutasi berproporsi sama."""
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    alerts = [
        make_alert(
            i,
            base_t + timedelta(minutes=i * 20),
            agent_id=f"agent_{(i % 3) + 1}",
            group="pam" if i % 2 == 0 else "syslog",
            level=(i % 12) + 1,
            crit=(i % 3) + 1,
        )
        for i in range(50)
    ]

    # Jalankan batch & latih model.
    batch_res = BatchResearchRunner(base_delta_t=timedelta(minutes=15), adaptive=False).run(alerts)
    bundle = train_reference_pipeline(batch_res.meta_alerts, random_state=42, model_version="eval-v1")
    scoring_pipe = ScoringPipeline(bundle)
    _, scored_metas = scoring_pipe.score_meta_alerts(batch_res.meta_alerts)

    result = run_structural_silhouette_evaluation(
        scored_metas=scored_metas,
        model_bundle=bundle,
        n_permutations=100,
        random_seed=42,
    )

    if result.is_calculable:
        assert -1.0 <= result.observed_silhouette <= 1.0
        assert result.n_valid_permutations == 100
        assert 0.0 <= result.observed_percentile <= 100.0
        assert 0.0 <= result.empirical_p_value <= 1.0
        assert result.random_mean is not None
        assert result.random_std is not None
        assert result.null_histogram is not None
        assert sum(result.null_histogram["counts"]) == result.n_valid_permutations
    else:
        # Bila partisi hanya punya 1 kelas, is_calculable bernilai False.
        assert result.uncalculable_reason is not None

def test_structural_silhouette_action_partitioning():
    """Pemetaan eksplisit serta edge case dua kelas/satu kelas untuk silhouette."""
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)

    # Buat bundle dummy untuk scaler.
    alerts = [
        make_alert(
            i,
            base_t + timedelta(minutes=i * 20),
            agent_id=f"agent_{(i % 3) + 1}",
            group="pam" if i % 2 == 0 else "syslog",
            level=(i % 12) + 1,
            crit=(i % 3) + 1,
        )
        for i in range(10)
    ]
    batch_res = BatchResearchRunner(base_delta_t=timedelta(minutes=15), adaptive=False).run(alerts)
    bundle = train_reference_pipeline(batch_res.meta_alerts, random_state=42, model_version="eval-v1")

    from src.contracts.scored_meta_alert import ScoredMetaAlert

    def mock_sma(action: str, decision: str, feat_val: float) -> ScoredMetaAlert:
        return ScoredMetaAlert(
            meta_id=1, agent_id="A", agent_name="A", rule_group_primary="P",
            start_time=base_t, end_time=base_t, alert_count=1, max_severity=1,
            mitre_tactics=(),
            seven_features={
                "max_severity": feat_val, "mitre_tactic_count": feat_val,
                "critical_mitre_tactic_present": feat_val, "alert_count_log": feat_val,
                "rule_diversity_shannon": feat_val, "severity_dispersion": feat_val,
                "agent_criticality": feat_val
            },
            raw_model_score=0.5, anomaly_score=0.5, threshold_used=0.5,
            decision=decision, action=action, escalate=(action=="ESCALATE"),
            model_version="v1", feature_schema_version="v1", score_calibration_version="v1",
            source_alert_ids=()
        )

    metas_two_class = [
        mock_sma("ESCALATE", "CRITICAL", 1.0),
        mock_sma("ESCALATE", "SUSPICIOUS", 1.0),
        mock_sma("DAILY_DIGEST", "CONTEXTUAL_ANOMALY", -1.0),
        mock_sma("SUPPRESS", "NOISE", -1.0)
    ]

    # Uji dua kelas yang terkendali.
    res_two = run_structural_silhouette_evaluation(metas_two_class, bundle, n_permutations=100)
    assert res_two.is_calculable is True
    assert res_two.n_valid_permutations == 100
    assert res_two.random_mean is not None

    # Uji satu kelas.
    metas_single = [
        mock_sma("SUPPRESS", "NOISE", 0.0),
        mock_sma("DAILY_DIGEST", "NOISE_HIGH", 0.0)
    ]
    res_single = run_structural_silhouette_evaluation(metas_single, bundle, n_permutations=100)
    assert res_single.is_calculable is False

    # Assertion pemetaan eksplisit.
    import numpy as np
    observed = np.array([1 if s.action == "ESCALATE" else 0 for s in metas_two_class], dtype=int)
    assert list(observed) == [1, 1, 0, 0]

