"""Paket evaluasi: reduksi RBTA, sensitivitas, ketahanan noise, runtime, dan struktur model."""

from src.evaluation.fixed_window_baseline import FixedWindowResult, run_fixed_window_baseline
from src.evaluation.metrics import MetricsError, compute_arr
from src.evaluation.noise_robustness import (
    NOISE_RATES,
    NoiseRobustnessResult,
    run_noise_robustness_evaluation,
)
from src.evaluation.runtime_complexity import (
    RuntimeComplexityResult,
    run_runtime_complexity_evaluation,
)
from src.evaluation.sensitivity import (
    SENSITIVITY_DELTA_T_MINUTES,
    SensitivityResult,
    run_delta_t_sensitivity_analysis,
)
from src.evaluation.structural_silhouette import (
    StructuralSilhouetteResult,
    run_structural_silhouette_evaluation,
)

__all__ = [
    "FixedWindowResult",
    "MetricsError",
    "NOISE_RATES",
    "NoiseRobustnessResult",
    "RuntimeComplexityResult",
    "SENSITIVITY_DELTA_T_MINUTES",
    "SensitivityResult",
    "StructuralSilhouetteResult",
    "compute_arr",
    "run_delta_t_sensitivity_analysis",
    "run_fixed_window_baseline",
    "run_noise_robustness_evaluation",
    "run_runtime_complexity_evaluation",
    "run_structural_silhouette_evaluation",
]
