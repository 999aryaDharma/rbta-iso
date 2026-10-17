"""Unit test ScoreCalibration."""
import pytest
from src.model.calibration import CalibrationError, ScoreCalibration


def test_score_calibration_valid():
    """Kalibrasi skor menskalakan skor anomali mentah di antara raw_min dan raw_max dengan benar."""
    cal = ScoreCalibration(raw_min=0.30, raw_max=0.70)
    assert cal.calibrate(0.30) == pytest.approx(0.0)
    assert cal.calibrate(0.70) == pytest.approx(1.0)
    assert cal.calibrate(0.50) == pytest.approx(0.5)
    # Ekstrapolasi di luar rentang reference dipertahankan tanpa pembatasan sembarangan.
    assert cal.calibrate(0.90) == pytest.approx(1.5)
    assert cal.calibrate(0.10) == pytest.approx(-0.5)


def test_score_calibration_degenerate_fails():
    """Bila raw_max <= raw_min, ScoreCalibration harus melempar CalibrationError."""
    with pytest.raises(CalibrationError, match="raw_max must be strictly greater than raw_min"):
        ScoreCalibration(raw_min=0.50, raw_max=0.50)

    with pytest.raises(CalibrationError, match="raw_max must be strictly greater than raw_min"):
        ScoreCalibration(raw_min=0.60, raw_max=0.40)


def test_score_calibration_serialization_roundtrip():
    """ScoreCalibration bisa diserialisasi ke/dari dict/json tanpa kehilangan data."""
    cal = ScoreCalibration(raw_min=0.25, raw_max=0.75, version="minmax-v1")
    data = cal.to_dict()
    assert data["raw_min"] == 0.25
    assert data["raw_max"] == 0.75
    assert data["higher_is_more_anomalous"] is True

    restored = ScoreCalibration.from_dict(data)
    assert restored.raw_min == cal.raw_min
    assert restored.raw_max == cal.raw_max
    assert restored.version == cal.version
