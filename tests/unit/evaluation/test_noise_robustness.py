"""Unit test evaluasi ketahanan noise."""
from datetime import datetime, timedelta, timezone
import pytest
import pandas as pd

from src.contracts.raw_alert import CanonicalRawAlert
from src.evaluation.noise_robustness import run_noise_robustness_evaluation, NOISE_RATES


def make_alert(idx: int, ts: datetime, agent_id: str = "001", group: str = "pam") -> CanonicalRawAlert:
    return CanonicalRawAlert(
        wazuh_alert_id=f"alert_{idx}",
        timestamp=ts,
        agent_id=agent_id,
        agent_name=f"soc-{agent_id}",
        rule_group_primary=group,
        rule_level=3,
        rule_id="5501",
        mitre_tactics=(),
        srcip=None,
        agent_criticality=1,
    )


def test_noise_robustness_evaluates_exact_five_noise_rates():
    """Uji ketahanan noise memakai tepat [0.0, 0.05, 0.10, 0.20, 0.30]."""
    assert NOISE_RATES == (0.0, 0.05, 0.10, 0.20, 0.30)

    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    alerts = [make_alert(i, base_t + timedelta(seconds=i * 30)) for i in range(100)]

    result = run_noise_robustness_evaluation(alerts, delta_t=timedelta(minutes=15), random_seed=42)

    assert isinstance(result.summary_df, pd.DataFrame)
    assert len(result.summary_df) == 15
    assert set(result.summary_df["variant"]) == {
        "time_only_fixed", "contextual_fixed", "contextual_adaptive"
    }
    assert sorted(result.summary_df["noise_rate"].unique()) == [0.0, 0.05, 0.10, 0.20, 0.30]
    assert result.summary_df.groupby("noise_rate")["injected_stream_sha256"].nunique().eq(1).all()

    # Kolom output wajib.
    required_cols = [
        "noise_rate",
        "variant",
        "n_noise",
        "n_total",
        "n_meta",
        "arr",
        "arr_degradation",
        "noise_absorption_count",
        "noise_absorption_rate",
        "execution_time_ms",
        "context_purity_percent",
        "injected_stream_sha256",
    ]
    for col in required_cols:
        assert col in result.summary_df.columns

    # Baseline noise 0% tidak mengalami degradasi.
    rows_0 = result.summary_df[result.summary_df["noise_rate"] == 0.0]
    assert rows_0["n_noise"].eq(0).all()
    assert rows_0["arr_degradation"].eq(0.0).all()


def test_noise_absorption_traceability():
    """Penyerapan noise dihitung dari MetaAlert.wazuh_alert_ids yang sebenarnya."""
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    alerts = [make_alert(i, base_t + timedelta(seconds=i * 10)) for i in range(50)]

    result = run_noise_robustness_evaluation(alerts, noise_rates=(0.0, 0.20), delta_t=timedelta(minutes=15), random_seed=42)
    row_20 = result.summary_df[
        (result.summary_df["noise_rate"] == 0.20)
        & (result.summary_df["variant"] == "contextual_adaptive")
    ].iloc[0]
    assert row_20["noise_rate"] == 0.20
    assert row_20["n_noise"] == 10
    assert 0 <= row_20["noise_absorption_count"] <= 10
    assert 0.0 <= row_20["noise_absorption_rate"] <= 100.0
