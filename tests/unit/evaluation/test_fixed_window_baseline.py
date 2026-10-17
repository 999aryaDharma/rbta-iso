"""Unit test baseline fixed tumbling time-window."""
from datetime import datetime, timedelta, timezone
import pytest

from src.contracts.raw_alert import CanonicalRawAlert
from src.evaluation.fixed_window_baseline import run_fixed_window_baseline


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


def test_fixed_window_baseline_slices_by_pure_time_window():
    """Baseline fixed window mempartisi event hanya berdasarkan window kalender, tanpa melihat agent atau rule group."""
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    alerts = [
        # Window 1: 10:00 - 10:15 (3 alert dari agent/group berbeda).
        make_alert(1, base_t + timedelta(minutes=0), agent_id="001", group="pam"),
        make_alert(2, base_t + timedelta(minutes=5), agent_id="002", group="syslog"),
        make_alert(3, base_t + timedelta(minutes=14), agent_id="003", group="web"),
        # Window 2: 10:15 - 10:30 (2 alert).
        make_alert(4, base_t + timedelta(minutes=16), agent_id="001", group="pam"),
        make_alert(5, base_t + timedelta(minutes=25), agent_id="001", group="pam"),
    ]

    result = run_fixed_window_baseline(alerts, window_duration=timedelta(minutes=15))

    assert result.n_raw == 5
    assert result.n_meta == 2
    assert result.arr == pytest.approx(60.0)
    assert len(result.meta_alerts) == 2
    assert result.meta_alerts[0].alert_count == 3
    assert result.meta_alerts[1].alert_count == 2

def test_fixed_window_baseline_calendar_anchoring():
    """Baseline fixed window berpatokan pada epoch kalender, bukan event pertama."""
    # Epoch 0 adalah 1970-01-01 00:00:00.
    # Pakai 10:07, yaitu 7 menit setelah awal window 10:00-10:15.
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    alerts = [
        # Window 1 (kalender 10:00-10:15).
        make_alert(1, base_t + timedelta(minutes=7), agent_id="001", group="pam"),
        make_alert(2, base_t + timedelta(minutes=14), agent_id="002", group="web"),
        # Window 2 (kalender 10:15-10:30).
        make_alert(3, base_t + timedelta(minutes=15), agent_id="001", group="pam"),
        make_alert(4, base_t + timedelta(minutes=21), agent_id="001", group="syslog"),
        make_alert(5, base_t + timedelta(minutes=29), agent_id="003", group="pam"),
        # Window 3 (kalender 10:30-10:45).
        make_alert(6, base_t + timedelta(minutes=30), agent_id="001", group="web"),
    ]

    result = run_fixed_window_baseline(alerts, window_duration=timedelta(minutes=15))

    assert result.n_raw == 6
    assert len(result.meta_alerts) == 3
    assert result.meta_alerts[0].alert_count == 2
    assert result.meta_alerts[1].alert_count == 3
    assert result.meta_alerts[2].alert_count == 1

    # agent_id/rule_group berbeda dalam window yang sama TIDAK dipisah.
    assert len(result.meta_alerts[1].rule_id_distribution) > 0 # semuanya digabung

