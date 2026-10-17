"""Evaluasi ketahanan terhadap noise dengan menyisipkan alert mirip false positive."""

from dataclasses import dataclass
from datetime import datetime, timedelta
import random
import hashlib
import json
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
import pandas as pd

from src.contracts.raw_alert import CanonicalRawAlert
from src.evaluation.metrics import compute_arr
from src.evaluation.context_quality import compute_context_quality
from src.evaluation.contextual_fixed_baseline import run_contextual_fixed_window_baseline
from src.evaluation.fixed_window_baseline import run_fixed_window_baseline
from src.runners.batch_runner import BatchResearchRunner

NOISE_RATES: Tuple[float, ...] = (0.0, 0.05, 0.10, 0.20, 0.30)


@dataclass(frozen=True)
class NoiseRobustnessResult:
    """Hasil evaluasi ketahanan noise."""

    summary_df: pd.DataFrame


def _generate_noise_alerts(
    clean_alerts: Sequence[CanonicalRawAlert],
    n_noise: int,
    rng: random.Random,
) -> List[CanonicalRawAlert]:
    """Bentuk alert noise mirip false positive dengan semantik agent/group yang tetap valid."""
    if not clean_alerts or n_noise <= 0:
        return []

    # Kumpulkan tuple agent yang valid (agent_id, agent_name, agent_criticality).
    agents = list({(a.agent_id, a.agent_name, a.agent_criticality) for a in clean_alerts})
    rule_groups = list({a.rule_group_primary for a in clean_alerts})
    min_ts = min(a.timestamp for a in clean_alerts)
    max_ts = max(a.timestamp for a in clean_alerts)
    span_sec = max(1.0, (max_ts - min_ts).total_seconds())

    noise_alerts: List[CanonicalRawAlert] = []
    for i in range(n_noise):
        agent_id, agent_name, agent_crit = rng.choice(agents)
        rule_grp = rng.choice(rule_groups)
        offset_sec = rng.uniform(0.0, span_sec)
        ts = min_ts + timedelta(seconds=offset_sec)
        sev = rng.randint(1, 4)

        noise_alerts.append(
            CanonicalRawAlert(
                wazuh_alert_id=f"noise_{i:06d}",
                timestamp=ts,
                agent_id=agent_id,
                agent_name=agent_name,
                rule_group_primary=rule_grp,
                rule_level=sev,
                rule_id=f"noise_rule_{rng.randint(1, 5)}",
                mitre_tactics=(),
                srcip=None,
                agent_criticality=agent_crit,
            )
        )

    return noise_alerts


def run_noise_robustness_evaluation(
    alerts: Iterable[CanonicalRawAlert],
    noise_rates: Sequence[float] = NOISE_RATES,
    delta_t: timedelta = timedelta(minutes=15),
    random_seed: int = 42,
) -> NoiseRobustnessResult:
    """Evaluasi ketahanan RBTA terhadap injeksi noise benign ber-severity rendah.

    Parameters
    ----------
    alerts : Iterable[CanonicalRawAlert]
        Dataset alert evaluasi yang bersih.
    noise_rates : Sequence[float]
        Proporsi injeksi noise yang dievaluasi (default: 0.0, 0.05, 0.10, 0.20, 0.30).
    delta_t : timedelta
        Window waktu agregasi.
    random_seed : int
        Seed acak deterministik.

    Returns
    -------
    NoiseRobustnessResult
        Ringkasan DataFrame untuk setiap level noise.
    """
    clean_list = list(alerts)
    n_clean = len(clean_list)
    rng = random.Random(random_seed)

    records: List[Dict[str, Any]] = []
    baseline_arr: Dict[str, float] = {}

    for rate in noise_rates:
        n_noise = int(round(n_clean * rate))
        noise_alerts = _generate_noise_alerts(clean_list, n_noise, rng)
        combined_stream = sorted(clean_list + noise_alerts, key=lambda a: a.timestamp)
        n_total = len(combined_stream)

        digest_payload = [
            [a.wazuh_alert_id, a.timestamp.isoformat(), a.agent_id, a.rule_group_primary, a.rule_level]
            for a in combined_stream
        ]
        stream_digest = hashlib.sha256(
            json.dumps(digest_payload, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

        variants = (
            ("time_only_fixed", lambda: run_fixed_window_baseline(combined_stream, delta_t)),
            ("contextual_fixed", lambda: run_contextual_fixed_window_baseline(combined_stream, delta_t)),
            (
                "contextual_adaptive",
                lambda: BatchResearchRunner(base_delta_t=delta_t, adaptive=True).run(combined_stream),
            ),
        )
        for variant, execute in variants:
            start_t = time.perf_counter()
            result = execute()
            exec_ms = (time.perf_counter() - start_t) * 1000.0
            metas = result.meta_alerts
            n_meta = len(metas)
            arr = compute_arr(n_total, n_meta) if n_total > 0 else 0.0

            if rate == 0.0:
                baseline_arr[variant] = arr
                degradation = 0.0
                absorption_count = 0
                absorption_rate = None
            else:
                degradation = float(baseline_arr.get(variant, arr) - arr)
                absorption_count = 0
                for meta in metas:
                    has_clean = any(not wid.startswith("noise_") for wid in meta.wazuh_alert_ids)
                    if has_clean:
                        absorption_count += sum(
                            1 for wid in meta.wazuh_alert_ids if wid.startswith("noise_")
                        )
                absorption_rate = (absorption_count / n_noise * 100.0) if n_noise else 100.0

            quality = compute_context_quality(metas, combined_stream)
            records.append({
                "noise_rate": rate,
                "variant": variant,
                "n_noise": n_noise,
                "n_total": n_total,
                "n_meta": n_meta,
                "arr": arr,
                "arr_degradation": degradation,
                "noise_absorption_count": absorption_count,
                "noise_absorption_rate": absorption_rate,
                "context_purity_percent": quality.context_purity_percent,
                "context_contamination_percent": quality.context_contamination_percent,
                "injected_stream_sha256": stream_digest,
                "execution_time_ms": exec_ms,
            })

    return NoiseRobustnessResult(summary_df=pd.DataFrame(records))
