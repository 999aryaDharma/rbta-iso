"""Unit test perhitungan TukeyThreshold."""
import pytest
from src.model.threshold import ThresholdError, TukeyThreshold, compute_tukey_threshold


def test_compute_tukey_threshold_normal_distribution():
    """Threshold Tukey Q3 + 1.5 * IQR dihitung akurat dari distribusi skor."""
    # Skor diskrit sederhana.
    scores = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
    tt = compute_tukey_threshold(scores)

    # Q1 dan Q3 memakai persentil numpy/pandas.
    assert tt.q1 < tt.q3
    assert tt.iqr == pytest.approx(tt.q3 - tt.q1)
    assert tt.threshold == pytest.approx(tt.q3 + 1.5 * tt.iqr)
    assert tt.method == "tukey_iqr"


def test_tukey_threshold_unclamped_greater_than_one():
    """Threshold Tukey TIDAK boleh dibatasi buatan ke 1.0."""
    scores = [0.8, 0.85, 0.9, 0.95, 1.0]
    tt = compute_tukey_threshold(scores)
    # Threshold memang akan melebihi 1.0.
    assert tt.threshold > 1.0


def test_compute_tukey_threshold_insufficient_samples_fails():
    """Kurang dari 4 sampel tidak cukup untuk menghitung IQR dengan andal."""
    with pytest.raises(ThresholdError, match="At least 4 score samples"):
        compute_tukey_threshold([0.5, 0.6])


def test_tukey_threshold_serialization_roundtrip():
    """TukeyThreshold bisa diserialisasi ke/dari dict."""
    tt = TukeyThreshold(q1=0.25, q3=0.75, iqr=0.50, threshold=1.50)
    data = tt.to_dict()
    restored = TukeyThreshold.from_dict(data)
    assert restored.q1 == tt.q1
    assert restored.q3 == tt.q3
    assert restored.iqr == tt.iqr
    assert restored.threshold == tt.threshold
