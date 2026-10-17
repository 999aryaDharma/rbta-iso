"""Unit test faktor kecepatan dan jeda ReplayClock."""
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
import pytest

from src.runners.clock import ClockError, ReplayClock


def test_replay_clock_speed_factors():
    """Clock menghitung jeda wall-clock sebagai gap event dibagi faktor kecepatan."""
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    next_t = base_t + timedelta(seconds=100)

    # Kecepatan 1x: gap 100 detik -> jeda 100 detik.
    c1 = ReplayClock(speed_factor=1.0)
    with patch("time.sleep") as mock_sleep:
        delay = c1.wait(base_t, next_t)
        assert delay == pytest.approx(100.0)
        mock_sleep.assert_called_once_with(pytest.approx(100.0))

    # Kecepatan 10x: gap 100 detik -> jeda 10 detik.
    c10 = ReplayClock(speed_factor=10.0)
    with patch("time.sleep") as mock_sleep:
        delay = c10.wait(base_t, next_t)
        assert delay == pytest.approx(10.0)
        mock_sleep.assert_called_once_with(pytest.approx(10.0))

    # Kecepatan 100x: gap 100 detik -> jeda 1.0 detik.
    c100 = ReplayClock(speed_factor=100.0)
    with patch("time.sleep") as mock_sleep:
        delay = c100.wait(base_t, next_t)
        assert delay == pytest.approx(1.0)
        mock_sleep.assert_called_once_with(pytest.approx(1.0))


def test_replay_clock_max_speed_does_not_sleep():
    """Kecepatan MAX tidak tidur (delay=0.0) dan tidak pernah memanggil time.sleep."""
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    next_t = base_t + timedelta(hours=5)

    c_max = ReplayClock(speed_factor="MAX")
    with patch("time.sleep") as mock_sleep:
        delay = c_max.wait(base_t, next_t)
        assert delay == 0.0
        mock_sleep.assert_not_called()


def test_replay_clock_retrograde_or_same_timestamp_does_not_sleep():
    """Bila timestamp berikutnya <= timestamp sebelumnya, jedanya 0.0."""
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    prev_t = base_t - timedelta(seconds=50)

    c = ReplayClock(speed_factor=1.0)
    with patch("time.sleep") as mock_sleep:
        delay = c.wait(base_t, prev_t)
        assert delay == 0.0
        mock_sleep.assert_not_called()


def test_replay_clock_invalid_speed_factor():
    """Faktor kecepatan tidak valid melempar ClockError."""
    with pytest.raises(ClockError, match="Invalid speed factor"):
        ReplayClock(speed_factor=0.0)

    with pytest.raises(ClockError, match="Invalid speed factor"):
        ReplayClock(speed_factor=-5.0)

    with pytest.raises(ClockError, match="Invalid speed factor"):
        ReplayClock(speed_factor="FAST")
