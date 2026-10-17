"""Runner replay stream yang menjalankan inferensi event demi event di atas Research Core yang sama."""

from datetime import datetime, timedelta
from typing import Iterable, Iterator, List, Optional

from src.config.research import DEFAULT_BASE_DELTA_T
from src.contracts.raw_alert import CanonicalRawAlert
from src.contracts.scored_meta_alert import ScoredMetaAlert
from src.model.scoring_pipeline import ScoringPipeline
from src.rbta.engine import RBTAEngine
from src.rbta.reorder_buffer import LosslessReorderBuffer
from src.runners.clock import ReplayClock


class ReplayStreamRunner:
    """Me-replay aliran raw alert dengan tempo wall-clock event-time dan inferensi online.

    Parameters
    ----------
    scoring_pipeline : ScoringPipeline
        Scoring pipeline model yang sudah dimuat (hanya inferensi).
    clock : ReplayClock | None
        Clock yang mengatur kecepatan replay (default: MAX / non-blocking).
    base_delta_t : timedelta
        Window waktu agregasi eksperimen.
    adaptive : bool
        Aktifkan adaptasi EMA per agent setelah warmup 100 event.
    reorder_capacity : int
        Kapasitas reorder buffer.
    """

    def __init__(
        self,
        scoring_pipeline: ScoringPipeline,
        clock: Optional[ReplayClock] = None,
        base_delta_t: timedelta = DEFAULT_BASE_DELTA_T,
        adaptive: bool = True,
        reorder_capacity: int = 50,
    ) -> None:
        self.scoring_pipeline: ScoringPipeline = scoring_pipeline
        self.clock: ReplayClock = clock or ReplayClock(speed_factor="MAX")
        self.base_delta_t: timedelta = base_delta_t
        self.adaptive: bool = adaptive
        self.reorder_capacity: int = reorder_capacity

    def run(self, alerts: Iterable[CanonicalRawAlert]) -> Iterator[ScoredMetaAlert]:
        """Alirkan raw alert kanonis, majukan replay clock, dan yield ScoredMetaAlert begitu terbentuk.

        Parameters
        ----------
        alerts : Iterable[CanonicalRawAlert]
            Aliran raw alert kanonis.

        Yields
        ------
        ScoredMetaAlert
            Meta-alert terskor dan terprioritaskan saat difinalkan oleh RBTA.
        """
        buffer = LosslessReorderBuffer(capacity=self.reorder_capacity)
        engine = RBTAEngine(base_delta_t=self.base_delta_t, adaptive=self.adaptive)
        prev_ts: Optional[datetime] = None

        for alert in alerts:
            # Majukan replay clock.
            self.clock.wait(prev_ts, alert.timestamp)
            prev_ts = alert.timestamp

            ready_alerts = buffer.push(alert)
            for ready in ready_alerts:
                finalized = engine.process(ready)
                for meta in finalized:
                    yield self.scoring_pipeline.score_single(meta)

        # Kuras reorder buffer.
        for ready in buffer.drain():
            finalized = engine.process(ready)
            for meta in finalized:
                yield self.scoring_pipeline.score_single(meta)

        # Kuras bucket aktif yang tersisa.
        for meta in engine.drain():
            yield self.scoring_pipeline.score_single(meta)
