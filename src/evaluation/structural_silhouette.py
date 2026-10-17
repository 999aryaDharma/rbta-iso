"""Evaluasi skor Silhouette struktural dan baseline null permutasi."""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence
import numpy as np
import pandas as pd
from sklearn.metrics import silhouette_score

from src.contracts.scored_meta_alert import ScoredMetaAlert
from src.features.extractor import FEATURE_COLUMNS, SevenFeatureExtractor
from src.model.scoring_pipeline import ModelArtifactBundle


@dataclass(frozen=True)
class StructuralSilhouetteResult:
    """Hasil evaluasi Silhouette struktural dan perbandingannya dengan baseline permutasi."""

    is_calculable: bool
    uncalculable_reason: Optional[str] = None
    observed_silhouette: Optional[float] = None
    random_mean: Optional[float] = None
    random_std: Optional[float] = None
    random_min: Optional[float] = None
    random_max: Optional[float] = None
    observed_percentile: Optional[float] = None
    z_score: Optional[float] = None
    empirical_p_value: Optional[float] = None
    n_valid_permutations: int = 0
    null_scores: Optional[List[float]] = None
    null_histogram: Optional[Dict[str, Any]] = None
    random_seed: int = 42


def run_structural_silhouette_evaluation(
    scored_metas: Sequence[ScoredMetaAlert],
    model_bundle: ModelArtifactBundle,
    n_permutations: int = 100,
    random_seed: int = 42,
) -> StructuralSilhouetteResult:
    """Evaluasi validitas struktur partisi keputusan terhadap baseline null permutasi.

    Parameters
    ----------
    scored_metas : Sequence[ScoredMetaAlert]
        Meta-alert terskor yang dievaluasi.
    model_bundle : ModelArtifactBundle
        Bundle model immutable yang berisi RobustScaler reference.
    n_permutations : int
        Jumlah permutasi label acak (default 100).
    random_seed : int
        Seed acak deterministik.

    Returns
    -------
    StructuralSilhouetteResult
        Silhouette terhitung, statistik distribusi null, z-score, dan p-value empiris.
    """
    if len(scored_metas) < 2:
        return StructuralSilhouetteResult(
            is_calculable=False,
            uncalculable_reason=f"Insufficient samples: requires at least 2 meta-alerts, got {len(scored_metas)}",
            random_seed=random_seed,
        )

    # Matriks fitur ter-skala X_scaled.
    records: List[Dict[str, float]] = []
    for s in scored_metas:
        feat_dict = {col: float(s.seven_features.get(col, 0.0)) for col in FEATURE_COLUMNS}
        records.append(feat_dict)

    df_feats = pd.DataFrame(records)[list(FEATURE_COLUMNS)]
    x_scaled = model_bundle.scaler.transform(df_feats)

    # Partisi biner untuk evaluasi: ESCALATE (1) vs non-ESCALATE (0).
    observed_partition = np.array([1 if s.action == "ESCALATE" else 0 for s in scored_metas], dtype=int)
    unique_classes = np.unique(observed_partition)

    if len(unique_classes) < 2:
        return StructuralSilhouetteResult(
            is_calculable=False,
            uncalculable_reason="Degenerate partition: all samples belong to a single class (cannot compute Silhouette score)",
            random_seed=random_seed,
        )

    # Skor Silhouette observasi.
    obs_sil = float(silhouette_score(x_scaled, observed_partition))

    # Baseline permutasi.
    rng = np.random.default_rng(random_seed)
    null_scores: List[float] = []

    for _ in range(n_permutations):
        shuffled_labels = rng.permutation(observed_partition)
        if len(np.unique(shuffled_labels)) < 2:
            continue
        score = float(silhouette_score(x_scaled, shuffled_labels))
        null_scores.append(score)

    if not null_scores:
        return StructuralSilhouetteResult(
            is_calculable=False,
            uncalculable_reason="Failed to compute any valid permutation scores",
            random_seed=random_seed,
        )

    null_arr = np.array(null_scores)
    r_mean = float(np.mean(null_arr))
    r_std = float(np.std(null_arr))
    r_min = float(np.min(null_arr))
    r_max = float(np.max(null_arr))

    # Persentil skor observasi di dalam distribusi null.
    percentile = float(np.mean(null_arr <= obs_sil) * 100.0)

    # Z-score terstandar.
    z_score = float((obs_sil - r_mean) / r_std) if r_std > 0 else 0.0

    # p-value empiris dengan koreksi sampel hingga:
    # p = (count(null >= obs) + 1) / (N + 1)
    k_greater_equal = int(np.sum(null_arr >= obs_sil))
    empirical_p = float((k_greater_equal + 1) / (len(null_scores) + 1))
    counts, edges = np.histogram(null_arr, bins=min(12, len(null_scores)))

    return StructuralSilhouetteResult(
        is_calculable=True,
        observed_silhouette=obs_sil,
        random_mean=r_mean,
        random_std=r_std,
        random_min=r_min,
        random_max=r_max,
        observed_percentile=percentile,
        z_score=z_score,
        empirical_p_value=empirical_p,
        n_valid_permutations=len(null_scores),
        null_scores=[float(score) for score in null_scores[:100]],
        null_histogram={"bin_edges": [float(edge) for edge in edges], "counts": [int(count) for count in counts]},
        random_seed=random_seed,
    )
