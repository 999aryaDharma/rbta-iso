"""Unit test evaluasi kompleksitas runtime dan throughput."""
from datetime import datetime, timedelta, timezone
import pytest
import pandas as pd

from src.contracts.raw_alert import CanonicalRawAlert
from src.evaluation.runtime_complexity import run_runtime_complexity_evaluation


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


def test_runtime_complexity_uses_repeated_median_measurements():
    """Bukti runtime memakai lima sampel per subset dan statistik ringkasan yang robust."""
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    alerts = [make_alert(i, base_t + timedelta(seconds=i * 5)) for i in range(160)]

    result = run_runtime_complexity_evaluation(alerts, n_subsets=8, delta_t=timedelta(minutes=15))

    assert isinstance(result.subset_df, pd.DataFrame)
    assert len(result.subset_df) == 8

    for col in [
        "n_alerts", "n_meta", "execution_time_ms", "execution_iqr_ms",
        "throughput_alerts_per_ms", "measurement_samples_ms",
    ]:
        assert col in result.subset_df.columns

    assert result.repetitions == 5
    assert result.preparation_time_ms >= 0
    assert result.subset_df["measurement_samples_ms"].map(len).eq(5).all()
    assert result.subset_df["execution_iqr_ms"].ge(0).all()
    assert 0.0 <= result.r_squared <= 1.0
    assert result.mean_throughput > 0
