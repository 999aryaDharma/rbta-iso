"""Konstanta konfigurasi metodologi RBTA yang dikunci."""
from datetime import timedelta

# Kunci metodologi (tidak boleh diubah).
EMA_ALPHA: float = 0.10
WARMUP_EVENT_TARGET: int = 100
MAX_BUCKET_DURATION: timedelta = timedelta(minutes=60)
ETW_MIN_MULTIPLIER: float = 0.5
ETW_MAX_MULTIPLIER: float = 1.5

# Parameter default eksperimen acuan.
DEFAULT_BASE_DELTA_T: timedelta = timedelta(minutes=15)
