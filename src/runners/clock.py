"""Replay clock yang mengatur tempo wall-clock event-time yang dipercepat."""

from datetime import datetime
import time
from typing import Union


class ClockError(ValueError):
    """Dilempar bila parameter replay clock tidak valid."""
    pass


class ReplayClock:
    """Mengatur tempo wall-clock untuk replay event historis.

    Parameters
    ----------
    speed_factor : float | str
        Pengali kecepatan replay (1.0, 10.0, 100.0, atau "MAX").
    """

    def __init__(self, speed_factor: Union[float, int, str] = "MAX") -> None:
        if isinstance(speed_factor, str):
            if speed_factor.upper() in ("MAX", "INF", "INFINITY"):
                self.speed_factor: float = float("inf")
            else:
                try:
                    val = float(speed_factor)
                    if val <= 0.0:
                        raise ValueError()
                    self.speed_factor = val
                except ValueError:
                    raise ClockError(f"Invalid speed factor string: '{speed_factor}'. Allowed: 1, 10, 100, 'MAX'")
        elif isinstance(speed_factor, (int, float)):
            if speed_factor <= 0:
                raise ClockError(f"Invalid speed factor: {speed_factor}. Must be > 0.")
            self.speed_factor = float(speed_factor)
        else:
            raise ClockError(f"Unsupported speed factor type: {type(speed_factor)}")

    def wait(self, previous_event_time: datetime, current_event_time: datetime) -> float:
        """Hitung lalu tunggu jeda wall-clock yang sesuai di antara dua event.

        Parameters
        ----------
        previous_event_time : datetime
            Timestamp event yang diproses sebelumnya.
        current_event_time : datetime
            Timestamp event yang sedang masuk.

        Returns
        -------
        float
            Jeda wall-clock yang ditunggu, dalam detik.
        """
        if self.speed_factor == float("inf"):
            return 0.0

        if previous_event_time is None or current_event_time is None:
            return 0.0

        gap_sec = (current_event_time - previous_event_time).total_seconds()
        if gap_sec <= 0.0:
            return 0.0

        delay = max(0.0, gap_sec / self.speed_factor)
        if delay > 0.0:
            time.sleep(delay)

        return delay
