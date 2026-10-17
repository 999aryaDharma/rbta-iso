"""Unit test analisis sensitivitas delta-t."""
from datetime import datetime, timedelta, timezone
import pytest
import pandas as pd

from src.contracts.raw_alert import CanonicalRawAlert
from src.evaluation.sensitivity import run_delta_t_sensitivity_analysis, SENSITIVITY_DELTA_T_MINUTES


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


def test_sensitivity_analysis_evaluates_exact_eight_delta_t_values():
    """Analisis sensitivitas menguji tepat [1, 5, 10, 15, 20, 30, 45, 60] menit dengan adaptive=False."""
    assert SENSITIVITY_DELTA_T_MINUTES == (1, 5, 10, 15, 20, 30, 45, 60)

    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    alerts = [make_alert(i, base_t + timedelta(minutes=i * 2)) for i in range(50)]

    result = run_delta_t_sensitivity_analysis(alerts)

    assert isinstance(result.summary_df, pd.DataFrame)
    assert len(result.summary_df) == 8
    assert list(result.summary_df["delta_t_min"]) == [1, 5, 10, 15, 20, 30, 45, 60]

    # Kolom output wajib.
    for col in ["delta_t_min", "n_raw", "n_meta", "arr", "execution_time_ms"]:
        assert col in result.summary_df.columns

    # delta_t elbow harus salah satu nilai yang diuji.
    assert result.recommended_elbow_delta_t in SENSITIVITY_DELTA_T_MINUTES
