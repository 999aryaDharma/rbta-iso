"""Evaluasi empiris kompleksitas runtime dan throughput."""

from dataclasses import dataclass
from datetime import timedelta
import time
from typing import Any, Dict, Iterable, List, Sequence, Tuple
import numpy as np
import pandas as pd
from scipy import stats

from src.contracts.raw_alert import CanonicalRawAlert
from src.runners.batch_runner import BatchResearchRunner


RUNTIME_EVALUATION_SUBSETS: int = 8


@dataclass(frozen=True)
class RuntimeComplexityResult:
    """Hasil evaluasi empiris kompleksitas runtime."""

    subset_df: pd.DataFrame
    slope: float
    intercept: float
    r_squared: float
    mean_throughput: float
    throughput_variation: float
    repetitions: int
    preparation_time_ms: float


def run_runtime_complexity_evaluation(
    alerts: Iterable[CanonicalRawAlert],
    n_subsets: int = RUNTIME_EVALUATION_SUBSETS,
    delta_t: timedelta = timedelta(minutes=15),
    repetitions: int = 5,
) -> RuntimeComplexityResult:
    """Ukur throughput RBTA pada subset data yang makin besar lalu fit regresi linear.

    Parameters
    ----------
    alerts : Iterable[CanonicalRawAlert]
        Dataset evaluasi.
    n_subsets : int
        Jumlah langkah skala (default 8).
    delta_t : timedelta
        Window agregasi.

    Returns
    -------
    RuntimeComplexityResult
        Pengukuran per subset, parameter regresi (slope, intercept, R^2), dan statistik throughput.
    """
    if repetitions < 3:
        raise ValueError("Runtime evaluation requires at least 3 repetitions")
    preparation_start = time.perf_counter()
    sorted_alerts = sorted(list(alerts), key=lambda a: a.timestamp)
    preparation_time_ms = (time.perf_counter() - preparation_start) * 1000.0
    total_len = len(sorted_alerts)

    subset_fractions = np.linspace(1.0 / n_subsets, 1.0, n_subsets)
    records: List[Dict[str, Any]] = []

    for frac in subset_fractions:
        k = max(1, int(round(total_len * frac)))
        subset = sorted_alerts[:k]

        # Panaskan cache dan jalur interpreter; sampel ini tidak ikut ke hasil.
        BatchResearchRunner(base_delta_t=delta_t, adaptive=True).run(subset)
        samples: List[float] = []
        n_meta_values: List[int] = []
        for _ in range(repetitions):
            runner = BatchResearchRunner(base_delta_t=delta_t, adaptive=True)
            start_t = time.perf_counter()
            res = runner.run(subset)
            samples.append(max(0.001, (time.perf_counter() - start_t) * 1000.0))
            n_meta_values.append(len(res.meta_alerts))
        if len(set(n_meta_values)) != 1:
            raise RuntimeError("Runtime repetitions produced non-deterministic meta-alert counts")

        exec_ms = float(np.median(samples))
        q1 = float(np.percentile(samples, 25))
        q3 = float(np.percentile(samples, 75))
        throughput = len(subset) / exec_ms

        records.append({
            "n_alerts": len(subset),
            "n_meta": n_meta_values[0],
            "execution_time_ms": exec_ms,
            "execution_q1_ms": q1,
            "execution_q3_ms": q3,
            "execution_iqr_ms": q3 - q1,
            "measurement_samples_ms": samples,
            "throughput_alerts_per_ms": throughput,
        })

    df = pd.DataFrame(records)

    # Regresi linear: n_alerts -> execution_time_ms
    x = df["n_alerts"].values
    y = df["execution_time_ms"].values

    slope, intercept, r_value, p_value, std_err = stats.linregress(x, y)
    r_squared = float(r_value ** 2)

    throughputs = df["throughput_alerts_per_ms"].values
    mean_thr = float(np.mean(throughputs))
    std_thr = float(np.std(throughputs))

    return RuntimeComplexityResult(
        subset_df=df,
        slope=float(slope),
        intercept=float(intercept),
        r_squared=r_squared,
        mean_throughput=mean_thr,
        throughput_variation=std_thr,
        repetitions=repetitions,
        preparation_time_ms=preparation_time_ms,
    )
