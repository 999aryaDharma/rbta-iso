"""src.streaming — simulasi streaming alert real-time.

Modul untuk menyimulasikan streaming alert online dari CSV statis, untuk menguji
pipeline RBTA + IF dalam kondisi offline (development/riset).

Komponen utama:
  - AlertStreamSimulator: emulator streaming
  - StreamStats: pengumpul statistik
  - setup_stream_logger: konfigurasi logging
"""

from .alert_stream_simulator import (
    AlertStreamSimulator,
    StreamStats,
    setup_stream_logger,
)

__all__ = [
    "AlertStreamSimulator",
    "StreamStats",
    "setup_stream_logger",
]
