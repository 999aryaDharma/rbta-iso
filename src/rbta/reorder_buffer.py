"""Reorder buffer event-time yang terbatas dan tanpa kehilangan alert, berbasis min-heap."""

import heapq
from typing import List, Tuple
from src.contracts.raw_alert import CanonicalRawAlert


class LosslessReorderBuffer:
    """Reorder buffer event-time yang terbatas dan deterministik.

    Jaminan:
    - Kompleksitas O(n log k) untuk kapasitas buffer k.
    - Tidak ada alert yang hilang.
    - Tie-breaker urutan kedatangan monoton, sehingga timestamp yang sama tetap FIFO.
    - Operasi drain idempoten.

    Parameters
    ----------
    capacity : int
        Jumlah maksimum alert yang ditahan sebelum alert paling awal dikeluarkan (harus >= 1).
    """

    def __init__(self, capacity: int = 1000) -> None:
        if capacity < 1:
            raise ValueError(f"Reorder buffer capacity must be >= 1, got {capacity}")
        self._capacity: int = capacity
        # Elemen heap: (timestamp, arrival_seq, CanonicalRawAlert)
        self._heap: List[Tuple[object, int, CanonicalRawAlert]] = []
        self._arrival_counter: int = 0

    @property
    def capacity(self) -> int:
        """Kapasitas maksimum reorder buffer."""
        return self._capacity

    def __len__(self) -> int:
        """Jumlah alert yang sedang ditahan."""
        return len(self._heap)

    def push(self, alert: CanonicalRawAlert) -> List[CanonicalRawAlert]:
        """Masukkan raw alert ke reorder buffer terbatas.

        Bila kapasitas terlampaui setelah dimasukkan, alert paling awal dikeluarkan.

        Parameters
        ----------
        alert : CanonicalRawAlert
            Raw alert yang masuk.

        Returns
        -------
        List[CanonicalRawAlert]
            Nol atau satu alert yang sudah siap dikeluarkan.
        """
        seq = self._arrival_counter
        self._arrival_counter += 1
        heapq.heappush(self._heap, (alert.timestamp, seq, alert))

        if len(self._heap) > self._capacity:
            _, _, earliest_alert = heapq.heappop(self._heap)
            return [earliest_alert]

        return []

    def drain(self) -> List[CanonicalRawAlert]:
        """Kuras dan kembalikan semua alert yang tersisa, urut naik menurut event-time.

        Pemanggilan berikutnya pada buffer kosong mengembalikan list kosong (idempoten).

        Returns
        -------
        List[CanonicalRawAlert]
            Semua alert yang tersisa, urut naik menurut event-time secara deterministik.
        """
        emitted: List[CanonicalRawAlert] = []
        while self._heap:
            _, _, alert = heapq.heappop(self._heap)
            emitted.append(alert)
        return emitted
