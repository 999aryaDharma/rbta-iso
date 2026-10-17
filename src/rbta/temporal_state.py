"""State temporal lokal per agent dan perhitungan Elastic Time Window (ETW) berbasis EMA."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Sequence

from src.config.research import (
    DEFAULT_BASE_DELTA_T,
    EMA_ALPHA,
    ETW_MAX_MULTIPLIER,
    ETW_MIN_MULTIPLIER,
    WARMUP_EVENT_TARGET,
)


class TemporalStateError(ValueError):
    """Dilempar bila state temporal menemui baseline tidak valid atau invarian waktu yang mustahil."""
    pass


@dataclass
class AgentTemporalState:
    """Mengelola state temporal yang independen per agent dan Elastic Time Window (ETW) adaptif.

    Attributes
    ----------
    agent_id : str
        ID unik agent Wazuh.
    base_delta_t : timedelta
        Window temporal baseline eksperimen.
    adaptive : bool
        Bila True, ETW adaptif berlaku setelah warmup 100 event. Bila False, base_delta_t tetap.
    last_timestamp : datetime | None
        Timestamp event-time tertinggi (monoton) yang teramati untuk agent ini.
    warmup_event_count : int
        Jumlah event valid yang diproses selama warmup (target = 100).
    warmup_gaps : list[float]
        Jeda antar-kedatangan (detik) yang dikumpulkan dari 100 event pertama.
    baseline_gap : float | None
        Rata-rata aritmetika jeda warmup (detik).
    ema_gap : float | None
        Exponential Moving Average jeda antar-kedatangan (detik).
    current_delta_t : timedelta
        Window waktu yang sedang aktif untuk agent ini.
    is_warmed_up : bool
        Penanda apakah warmup 100 event sudah selesai.
    _is_terminal_invalid : bool
        Penanda baseline warmup tidak valid, yang menonaktifkan instance state ini secara permanen.
    _invalid_reason : str | None
        Penjelasan kegagalan terminal tersebut.
    """

    agent_id: str
    # Hanya metadata observasi: tidak pernah dipakai untuk kunci bucket RBTA atau perhitungan ETW.
    agent_name: str = "unknown"
    base_delta_t: timedelta = DEFAULT_BASE_DELTA_T
    adaptive: bool = True
    last_timestamp: datetime | None = None
    warmup_event_count: int = 0
    warmup_gaps: list[float] = field(default_factory=list)
    baseline_gap: float | None = None
    ema_gap: float | None = None
    current_delta_t: timedelta = field(init=False)
    is_warmed_up: bool = False
    _is_terminal_invalid: bool = False
    _invalid_reason: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.base_delta_t, timedelta) or self.base_delta_t.total_seconds() <= 0:
            raise TemporalStateError(f"base_delta_t must be a positive timedelta, got {self.base_delta_t}")
        self.current_delta_t = self.base_delta_t

    def snapshot(self) -> "AgentTemporalState":
        """Salinan defensif yang terisolasi dari state temporal ini untuk operasi transaksional."""
        copied = AgentTemporalState(
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            base_delta_t=self.base_delta_t,
            adaptive=self.adaptive,
        )
        copied.last_timestamp = self.last_timestamp
        copied.warmup_event_count = self.warmup_event_count
        copied.warmup_gaps = list(self.warmup_gaps)
        copied.baseline_gap = self.baseline_gap
        copied.ema_gap = self.ema_gap
        copied.current_delta_t = self.current_delta_t
        copied.is_warmed_up = self.is_warmed_up
        copied._is_terminal_invalid = self._is_terminal_invalid
        copied._invalid_reason = self._invalid_reason
        return copied

    def observe(self, timestamp: datetime) -> timedelta:
        """Amati timestamp event yang masuk untuk agent ini dan kembalikan delta_t yang aktif.

        Parameters
        ----------
        timestamp : datetime
            Timestamp event yang timezone-aware.

        Returns
        -------
        timedelta
            Window agregasi yang aktif untuk event ini.

        Raises
        ------
        TemporalStateError
            Bila timestamp naive, state sudah terminal-invalid, atau jeda baseline warmup <= 0.
        """
        if timestamp.tzinfo is None:
            raise TemporalStateError("Observed timestamp must be timezone-aware (tzinfo cannot be None)")

        # State yang sudah gagal permanen.
        if self._is_terminal_invalid:
            raise TemporalStateError(
                f"AgentTemporalState for agent '{self.agent_id}' is in a terminal invalid state: {self._invalid_reason}"
            )

        # Mode tetap (adaptive=False).
        if not self.adaptive:
            if self.last_timestamp is None:
                self.last_timestamp = timestamp
                self.warmup_event_count = 1
                return self.current_delta_t

            self.warmup_event_count += 1
            if timestamp > self.last_timestamp:
                self.last_timestamp = timestamp
            return self.current_delta_t

        # Inisialisasi pada event pertama.
        if self.last_timestamp is None:
            self.last_timestamp = timestamp
            self.warmup_event_count = 1
            return self.current_delta_t

        # Fase warmup (event ke-2 sampai ke-100).
        if not self.is_warmed_up:
            self.warmup_event_count += 1

            # Hanya kedatangan maju/monoton yang menyumbang jeda valid non-negatif.
            if timestamp >= self.last_timestamp:
                gap_sec = (timestamp - self.last_timestamp).total_seconds()
                self.warmup_gaps.append(gap_sec)
                self.last_timestamp = timestamp

            # Cek apakah event ke-100 baru saja menyelesaikan warmup.
            if self.warmup_event_count >= WARMUP_EVENT_TARGET:
                if not self.warmup_gaps or sum(self.warmup_gaps) <= 0:
                    self._is_terminal_invalid = True
                    self._invalid_reason = (
                        f"baseline gap is <= 0 after {self.warmup_event_count} warmup events "
                        f"(sum={sum(self.warmup_gaps) if self.warmup_gaps else 0})"
                    )
                    raise TemporalStateError(
                        f"Agent '{self.agent_id}' baseline gap is <= 0 or undefined after "
                        f"{self.warmup_event_count} warmup events (sum={sum(self.warmup_gaps) if self.warmup_gaps else 0})"
                    )

                self.baseline_gap = sum(self.warmup_gaps) / len(self.warmup_gaps)
                self.ema_gap = self.baseline_gap
                self.is_warmed_up = True
                # Event ke-100 masih memakai base_delta_t; update adaptif mulai event ke-101.

            return self.current_delta_t

        # Fase adaptif setelah warmup (event ke-101 dan seterusnya), untuk kedatangan maju.
        if timestamp >= self.last_timestamp:
            current_gap = (timestamp - self.last_timestamp).total_seconds()
            self.last_timestamp = timestamp

            # Rumus EMA: ema_gap = alpha * current_gap + (1 - alpha) * prev_ema
            assert self.ema_gap is not None
            assert self.baseline_gap is not None
            self.ema_gap = (EMA_ALPHA * current_gap) + ((1.0 - EMA_ALPHA) * self.ema_gap)

            # Skala proporsional: ratio = ema_gap / baseline_gap
            ratio = self.ema_gap / self.baseline_gap
            candidate_sec = self.base_delta_t.total_seconds() * ratio

            # Dibatasi ke [0.5 * base, 1.5 * base].
            min_sec = ETW_MIN_MULTIPLIER * self.base_delta_t.total_seconds()
            max_sec = ETW_MAX_MULTIPLIER * self.base_delta_t.total_seconds()
            clamped_sec = min(max(candidate_sec, min_sec), max_sec)

            self.current_delta_t = timedelta(seconds=clamped_sec)

        # Catatan: bila timestamp < last_timestamp (event residual out-of-order),
        # last_timestamp TIDAK dimundurkan dan jeda negatif TIDAK dimasukkan ke EMA.

        return self.current_delta_t
