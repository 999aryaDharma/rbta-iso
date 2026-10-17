"""Analisis sensitivitas delta-t pada delapan durasi window statis."""

from dataclasses import dataclass
from datetime import timedelta
import time
from typing import Any, Dict, Iterable, List, Sequence, Tuple
import numpy as np
import pandas as pd

from src.contracts.raw_alert import CanonicalRawAlert
from src.evaluation.metrics import compute_arr
from src.runners.batch_runner import BatchResearchRunner

SENSITIVITY_DELTA_T_MINUTES: Tuple[int, ...] = (1, 5, 10, 15, 20, 30, 45, 60)


@dataclass(frozen=True)
class SensitivityResult:
    """Hasil evaluasi sensitivitas delta-t."""

    summary_df: pd.DataFrame
    recommended_elbow_delta_t: int


def _find_elbow_point(x_vals: Sequence[float], y_vals: Sequence[float]) -> int:
    """Cari titik elbow optimal dengan jarak tegak lurus terbesar ke garis secant."""
    if len(x_vals) < 3:
        return int(x_vals[0])

    p1 = np.array([x_vals[0], y_vals[0]])
    p2 = np.array([x_vals[-1], y_vals[-1]])

    line_vec = p2 - p1
    line_len = np.linalg.norm(line_vec)
    if line_len == 0:
        return int(x_vals[0])

    distances = []
    v1 = p2 - p1
    for x, y in zip(x_vals, y_vals):
        v2 = p1 - np.array([x, y])
        # Cross product 2D: x1*y2 - y1*x2
        cross_2d = float(v1[0] * v2[1] - v1[1] * v2[0])
        d = abs(cross_2d) / line_len
        distances.append(d)

    best_idx = int(np.argmax(distances))
    return int(x_vals[best_idx])


def run_delta_t_sensitivity_analysis(
    alerts: Iterable[CanonicalRawAlert],
    delta_t_values: Sequence[int] = SENSITIVITY_DELTA_T_MINUTES,
) -> SensitivityResult:
    """Jalankan agregasi batch RBTA pada nilai delta-t statis dengan ETW adaptif dimatikan.

    Parameters
    ----------
    alerts : Iterable[CanonicalRawAlert]
        Dataset alert evaluasi.
    delta_t_values : Sequence[int]
        Nilai delta-t dalam menit yang dievaluasi (default: 1, 5, 10, 15, 20, 30, 45, 60).

    Returns
    -------
    SensitivityResult
        Ringkasan DataFrame dan rekomendasi elbow.
    """
    alert_list = list(alerts)
    n_raw = len(alert_list)

    records: List[Dict[str, Any]] = []

    for dt_min in delta_t_values:
        runner = BatchResearchRunner(
            base_delta_t=timedelta(minutes=dt_min),
            adaptive=False,  # ceteris paribus ketat
        )

        start_time = time.perf_counter()
        result = runner.run(alert_list)
        exec_ms = (time.perf_counter() - start_time) * 1000.0

        n_meta = len(result.meta_alerts)
        arr = compute_arr(n_raw, n_meta) if n_raw > 0 else 0.0

        records.append({
            "delta_t_min": dt_min,
            "n_raw": n_raw,
            "n_meta": n_meta,
            "arr": arr,
            "execution_time_ms": exec_ms,
        })

    df = pd.DataFrame(records)

    # Hitung titik elbow dari kurva ARR.
    x_vals = [r["delta_t_min"] for r in records]
    y_vals = [r["arr"] for r in records]
    elbow_dt = _find_elbow_point(x_vals, y_vals)

    return SensitivityResult(
        summary_df=df,
        recommended_elbow_delta_t=elbow_dt,
    )
