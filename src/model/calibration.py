"""Kalibrasi skor anomali model."""

from dataclasses import dataclass
from typing import Any, Dict


class CalibrationError(ValueError):
    """Dilempar bila batas kalibrasi skor tidak valid atau degenerate."""
    pass


@dataclass(frozen=True)
class ScoreCalibration:
    """Kalibrasi skor min-max yang aman untuk stream, dipelajari saat run reference/training.

    Attributes
    ----------
    raw_min : float
        Skor anomali mentah terkecil pada dataset reference.
    raw_max : float
        Skor anomali mentah terbesar pada dataset reference.
    higher_is_more_anomalous : bool
        Apakah skor mentah yang lebih tinggi berarti lebih anomali (default True).
    version : str
        ID kebijakan kalibrasi.
    """

    raw_min: float
    raw_max: float
    higher_is_more_anomalous: bool = True
    version: str = "minmax-v1"

    def __post_init__(self) -> None:
        if self.raw_max <= self.raw_min:
            raise CalibrationError(
                f"Degenerate calibration: raw_max must be strictly greater than raw_min, got raw_min={self.raw_min}, raw_max={self.raw_max}"
            )

    def calibrate(self, raw_score: float) -> float:
        """Kalibrasi skor anomali mentah menjadi skor yang dinormalisasi terhadap reference.

        Parameters
        ----------
        raw_score : float
            Skor anomali mentah model (mis. -score_samples).

        Returns
        -------
        float
            Skor anomali ternormalisasi; baseline reference berada di kisaran ~[0.0, 1.0].
        """
        return (raw_score - self.raw_min) / (self.raw_max - self.raw_min)

    def to_dict(self) -> Dict[str, Any]:
        """Serialisasi parameter kalibrasi ke dict."""
        return {
            "version": self.version,
            "raw_min": float(self.raw_min),
            "raw_max": float(self.raw_max),
            "higher_is_more_anomalous": bool(self.higher_is_more_anomalous),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScoreCalibration":
        """Deserialisasi parameter kalibrasi dari dict."""
        return cls(
            raw_min=float(data["raw_min"]),
            raw_max=float(data["raw_max"]),
            higher_is_more_anomalous=bool(data.get("higher_is_more_anomalous", True)),
            version=str(data.get("version", "minmax-v1")),
        )
