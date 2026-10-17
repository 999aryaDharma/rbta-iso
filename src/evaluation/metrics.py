"""Metrik evaluasi Alert Reduction Rate (ARR)."""


class MetricsError(ValueError):
    """Dilempar bila input perhitungan metrik tidak valid."""
    pass


def compute_arr(n_raw: int, n_meta: int) -> float:
    """Hitung Alert Reduction Rate (ARR).

    Rumus:
    ARR = ((N_raw - N_meta) / N_raw) * 100.0%

    Parameters
    ----------
    n_raw : int
        Jumlah raw alert.
    n_meta : int
        Jumlah meta-alert hasil agregasi.

    Returns
    -------
    float
        Persentase reduksi alert [0.0, 100.0].

    Raises
    ------
    MetricsError
        Bila n_raw <= 0, n_meta < 0, atau n_meta > n_raw.
    """
    if n_raw <= 0:
        raise MetricsError(f"n_raw must be positive, got {n_raw}")
    if n_meta < 0:
        raise MetricsError(f"n_meta cannot be negative, got {n_meta}")
    if n_meta > n_raw:
        raise MetricsError(f"n_meta cannot exceed n_raw ({n_meta} > {n_raw})")

    return float((n_raw - n_meta) / n_raw * 100.0)
