"""Unit test metrik evaluasi."""
import pytest
from src.evaluation.metrics import compute_arr, MetricsError


def test_compute_arr_formula():
    """ARR dihitung sebagai (n_raw - n_meta) / n_raw * 100%."""
    assert compute_arr(1000, 200) == pytest.approx(80.0)
    assert compute_arr(100, 100) == pytest.approx(0.0)
    assert compute_arr(100, 10) == pytest.approx(90.0)
    assert compute_arr(100, 1) == pytest.approx(99.0)


def test_compute_arr_invalid_inputs():
    """ARR melempar MetricsError untuk jumlah negatif, raw alert nol, atau n_meta > n_raw."""
    with pytest.raises(MetricsError, match="n_raw must be positive"):
        compute_arr(0, 0)

    with pytest.raises(MetricsError, match="n_raw must be positive"):
        compute_arr(-10, 5)

    with pytest.raises(MetricsError, match="n_meta cannot be negative"):
        compute_arr(100, -5)

    with pytest.raises(MetricsError, match="n_meta cannot exceed n_raw"):
        compute_arr(100, 105)
