"""Perhitungan threshold anomali Tukey IQR."""

from dataclasses import dataclass
from typing import Any, Dict, Sequence
import numpy as np


class ThresholdError(ValueError):
    """Dilempar bila threshold tidak bisa dihitung dari distribusi skor."""
    pass


@dataclass(frozen=True)
class TukeyThreshold:
    """Definisi threshold anomali Tukey IQR.

    Attributes
    ----------
    q1 : float
        Persentil ke-25 skor reference ternormalisasi.
    q3 : float
        Persentil ke-75 skor reference ternormalisasi.
    iqr : float
        Interquartile range (q3 - q1).
    threshold : float
        Batas outlier (q3 + 1.5 * iqr).
    method : str
        ID metodologi.
    """

    q1: float
    q3: float
    iqr: float
    threshold: float
    method: str = "tukey_iqr"

    def to_dict(self) -> Dict[str, Any]:
        """Serialisasi threshold ke dict."""
        return {
            "method": self.method,
            "q1": float(self.q1),
            "q3": float(self.q3),
            "iqr": float(self.iqr),
            "threshold": float(self.threshold),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TukeyThreshold":
        """Deserialisasi threshold dari dict."""
        return cls(
            q1=float(data["q1"]),
            q3=float(data["q3"]),
            iqr=float(data["iqr"]),
            threshold=float(data["threshold"]),
            method=str(data.get("method", "tukey_iqr")),
        )


def compute_tukey_threshold(scores: Sequence[float]) -> TukeyThreshold:
    """Hitung threshold Tukey IQR dari sekumpulan skor anomali reference.

    Rumus:
        Q1 = persentil 25
        Q3 = persentil 75
        IQR = Q3 - Q1
        threshold = Q3 + 1.5 * IQR

    Catatan: threshold TIDAK dibatasi <= 1.0.

    Parameters
    ----------
    scores : Sequence[float]
        Skor anomali reference ternormalisasi.

    Returns
    -------
    TukeyThreshold
        Dataclass threshold hasil perhitungan.

    Raises
    ------
    ThresholdError
        Bila sampel skor kurang dari 4.
    """
    if len(scores) < 4:
        raise ThresholdError(f"At least 4 score samples are required to compute Tukey IQR, got {len(scores)}")

    arr = np.asarray(scores, dtype=np.float64)
    q1 = float(np.percentile(arr, 25))
    q3 = float(np.percentile(arr, 75))
    iqr = q3 - q1
    threshold = q3 + (1.5 * iqr)

    return TukeyThreshold(q1=q1, q3=q3, iqr=iqr, threshold=threshold)
