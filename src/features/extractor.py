"""Ekstraktor tujuh fitur kanonis dari representasi MetaAlert RBTA."""

import math
from typing import Any, Mapping, Sequence
import pandas as pd

from src.contracts.meta_alert import MetaAlert

FEATURE_COLUMNS: tuple[str, ...] = (
    "max_severity",
    "mitre_tactic_count",
    "critical_mitre_tactic_present",
    "alert_count_log",
    "rule_diversity_shannon",
    "severity_dispersion",
    "agent_criticality",
)


class FeatureExtractionError(ValueError):
    """Dilempar bila MetaAlert rusak atau nilai fitur tidak bisa dihitung."""
    pass


def compute_rule_diversity_shannon(rule_id_distribution: Mapping[str, int]) -> float:
    """Hitung entropi Shannon ternormalisasi H_norm = H / ln(k) untuk distribusi rule ID.

    Parameters
    ----------
    rule_id_distribution : Mapping[str, int]
        Pemetaan rule ID Wazuh ke jumlahnya.

    Returns
    -------
    float
        Entropi Shannon ternormalisasi dalam rentang [0.0, 1.0]. Bernilai 0.0 bila k <= 1.
    """
    counts = [c for c in rule_id_distribution.values() if c > 0]
    k = len(counts)
    if k <= 1:
        return 0.0

    total_count = sum(counts)
    if total_count <= 0:
        return 0.0

    h_entropy = 0.0
    for count in counts:
        p_i = count / total_count
        if p_i > 0.0:
            h_entropy -= p_i * math.log(p_i)

    max_entropy = math.log(k)
    if max_entropy <= 0.0:
        return 0.0

    h_norm = h_entropy / max_entropy
    return min(max(h_norm, 0.0), 1.0)


def compute_severity_dispersion(severity_distribution: Mapping[int, int]) -> float:
    """Hitung simpangan baku populasi dari level severity dalam bucket.

    Parameters
    ----------
    severity_distribution : Mapping[int, int]
        Pemetaan level severity rule ke jumlahnya.

    Returns
    -------
    float
        Simpangan baku populasi severity. Bernilai 0.0 untuk singleton atau severity yang seragam.
    """
    total_count = sum(severity_distribution.values())
    if total_count <= 1:
        return 0.0

    weighted_sum = sum(sev * cnt for sev, cnt in severity_distribution.items())
    mean_sev = weighted_sum / total_count

    variance = sum(cnt * ((sev - mean_sev) ** 2) for sev, cnt in severity_distribution.items()) / total_count
    return math.sqrt(max(variance, 0.0))


class SevenFeatureExtractor:
    """Mengekstrak tepat 7 fitur penelitian kanonis dari DTO MetaAlert."""

    @staticmethod
    def extract_features_dict(meta: MetaAlert) -> dict[str, float]:
        """Ekstrak fitur sebagai dict berurutan.

        Parameters
        ----------
        meta : MetaAlert
            Instance MetaAlert immutable.

        Returns
        -------
        dict[str, float]
            Dict 7 nama fitur ke nilai float.

        Raises
        ------
        FeatureExtractionError
            Bila meta tidak punya atribut wajib atau nilainya tidak valid/tidak finite.
        """
        try:
            alert_count = meta.alert_count
            max_severity = meta.max_severity
            mitre_tactics = meta.mitre_tactics_unique
            critical_mitre = meta.critical_mitre_present
            agent_criticality = meta.agent_criticality
            rule_dist = meta.rule_id_distribution
            sev_dist = meta.severity_distribution
        except AttributeError as exc:
            raise FeatureExtractionError(f"Missing or invalid MetaAlert attributes: {exc}") from exc

        if alert_count < 1:
            raise FeatureExtractionError(f"alert_count must be >= 1, got {alert_count}")

        feat_dict: dict[str, float] = {
            "max_severity": float(max_severity),
            "mitre_tactic_count": float(len(mitre_tactics)),
            "critical_mitre_tactic_present": 1.0 if critical_mitre else 0.0,
            "alert_count_log": float(math.log1p(alert_count)),
            "rule_diversity_shannon": float(compute_rule_diversity_shannon(rule_dist)),
            "severity_dispersion": float(compute_severity_dispersion(sev_dist)),
            "agent_criticality": float(agent_criticality),
        }

        for k, v in feat_dict.items():
            if not math.isfinite(v):
                raise FeatureExtractionError(f"Feature '{k}' evaluated to non-finite value: {v}")

        return feat_dict

    @classmethod
    def extract_features_vector(cls, meta: MetaAlert) -> tuple[float, ...]:
        """Ekstrak fitur sebagai tuple float dengan urutan persis FEATURE_COLUMNS.

        Parameters
        ----------
        meta : MetaAlert
            Instance MetaAlert immutable.

        Returns
        -------
        tuple[float, ...]
            Tuple 7 elemen sesuai urutan fitur kanonis.
        """
        f_dict = cls.extract_features_dict(meta)
        return tuple(f_dict[col] for col in FEATURE_COLUMNS)

    @classmethod
    def extract_features_df(cls, metas: Sequence[MetaAlert]) -> pd.DataFrame:
        """Ekstrak fitur dari sekumpulan MetaAlert ke DataFrame pandas.

        Parameters
        ----------
        metas : Sequence[MetaAlert]
            Urutan instance MetaAlert.

        Returns
        -------
        pd.DataFrame
            DataFrame dengan kolom persis FEATURE_COLUMNS, dtype float64.
        """
        rows = [cls.extract_features_dict(m) for m in metas]
        df = pd.DataFrame(rows, columns=list(FEATURE_COLUMNS))
        return df.astype("float64")
