"""Baseline fixed tumbling time-window (hanya waktu, tanpa konteks)."""

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Sequence, Tuple

from src.contracts.meta_alert import MetaAlert
from src.contracts.raw_alert import CanonicalRawAlert
from src.evaluation.metrics import compute_arr


@dataclass(frozen=True)
class FixedWindowResult:
    """Hasil evaluasi baseline Fixed Tumbling Window."""

    n_raw: int
    n_meta: int
    arr: float
    meta_alerts: List[MetaAlert]


def run_fixed_window_baseline(
    alerts: Iterable[CanonicalRawAlert],
    window_duration: timedelta = timedelta(minutes=15),
) -> FixedWindowResult:
    """Partisi raw alert murni berdasarkan window waktu kalender (tumbling).

    Parameters
    ----------
    alerts : Iterable[CanonicalRawAlert]
        Urutan raw alert kanonis yang masuk.
    window_duration : timedelta
        Durasi window tetap (default 15 menit).

    Returns
    -------
    FixedWindowResult
        Hasil agregasi dan ARR baseline fixed-window.
    """
    return _run_tumbling_window_baseline(alerts, window_duration, contextual=False)


def _run_tumbling_window_baseline(
    alerts: Iterable[CanonicalRawAlert],
    window_duration: timedelta,
    *,
    contextual: bool,
) -> FixedWindowResult:
    """Agregator window kalender yang dipakai bersama oleh dua baseline ablation."""
    sorted_alerts = sorted(list(alerts), key=lambda a: a.timestamp)
    n_raw = len(sorted_alerts)

    if n_raw == 0:
        return FixedWindowResult(n_raw=0, n_meta=0, arr=0.0, meta_alerts=[])

    window_sec = window_duration.total_seconds()
    windows: Dict[Tuple[int, str, str], List[CanonicalRawAlert]] = {}

    for a in sorted_alerts:
        bucket_idx = int(a.timestamp.timestamp() // window_sec)
        bucket_key = (
            bucket_idx,
            a.agent_id if contextual else "*",
            a.rule_group_primary if contextual else "*",
        )
        windows.setdefault(bucket_key, []).append(a)

    meta_alerts: List[MetaAlert] = []
    meta_id = 1

    for bucket_key in sorted(windows.keys()):
        bucket_idx = bucket_key[0]
        b_alerts = windows[bucket_key]
        start_t = b_alerts[0].timestamp
        end_t = b_alerts[-1].timestamp
        count = len(b_alerts)
        max_sev = max(a.rule_level for a in b_alerts)

        rule_counts = Counter(a.rule_id for a in b_alerts)
        sev_counts = Counter(a.rule_level for a in b_alerts)

        # Baseline ini menggabungkan lintas agent/group.
        first_a = b_alerts[0]
        agent_id = "baseline_mixed" if len(set(a.agent_id for a in b_alerts)) > 1 else first_a.agent_id
        agent_name = "baseline_mixed" if len(set(a.agent_name for a in b_alerts)) > 1 else first_a.agent_name
        rule_group = "baseline_mixed" if len(set(a.rule_group_primary for a in b_alerts)) > 1 else first_a.rule_group_primary
        agent_crit = max(a.agent_criticality for a in b_alerts)

        mitre_tactics: List[str] = []
        for a in b_alerts:
            for t in a.mitre_tactics:
                if t not in mitre_tactics:
                    mitre_tactics.append(t)

        crit_mitre = any(t in ("Initial Access", "Execution", "Impact", "Lateral Movement", "Exfiltration") for t in mitre_tactics)

        meta = MetaAlert(
            meta_id=meta_id,
            agent_id=agent_id,
            agent_name=agent_name,
            rule_group_primary=rule_group,
            start_time=start_t,
            end_time=end_t,
            alert_count=count,
            max_severity=max_sev,
            rule_id_distribution=dict(rule_counts),
            severity_distribution=dict(sev_counts),
            mitre_tactics_unique=tuple(mitre_tactics),
            critical_mitre_present=crit_mitre,
            agent_criticality=agent_crit,
            wazuh_alert_ids=tuple(a.wazuh_alert_id for a in b_alerts),
            metadata={
                "baseline_window_idx": bucket_idx,
                "baseline_variant": "contextual_fixed" if contextual else "time_only_fixed",
            },
        )
        meta_alerts.append(meta)
        meta_id += 1

    n_meta = len(meta_alerts)
    arr = compute_arr(n_raw, n_meta)

    return FixedWindowResult(
        n_raw=n_raw,
        n_meta=n_meta,
        arr=arr,
        meta_alerts=meta_alerts,
    )
