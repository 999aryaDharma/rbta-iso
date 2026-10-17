"""Batch runner untuk eksperimen penelitian, analisis sensitivitas, dan pembuatan artefak offline."""

from dataclasses import dataclass
from datetime import timedelta
from typing import Iterable, List, Optional, Tuple
import pandas as pd

from src.config.research import DEFAULT_BASE_DELTA_T
from src.contracts.meta_alert import MetaAlert
from src.contracts.raw_alert import CanonicalRawAlert
from src.contracts.scored_meta_alert import ScoredMetaAlert
from src.features.extractor import SevenFeatureExtractor
from src.model.scoring_pipeline import ScoringPipeline
from src.rbta.engine import RBTAEngine
from src.rbta.reorder_buffer import LosslessReorderBuffer


@dataclass(frozen=True)
class BatchRunResult:
    """Bundle output yang dihasilkan BatchResearchRunner."""

    meta_alerts: List[MetaAlert]
    features_df: pd.DataFrame
    scored_meta_alerts: Optional[List[ScoredMetaAlert]] = None
    scored_df: Optional[pd.DataFrame] = None


class BatchResearchRunner:
    """Pemrosesan batch offline ber-throughput tinggi memakai Research Core yang sama.

    Parameters
    ----------
    base_delta_t : timedelta
        Window waktu agregasi eksperimen.
    adaptive : bool
        Aktifkan adaptasi EMA per agent setelah warmup 100 event.
    reorder_capacity : int
        Kapasitas reorder buffer.
    scoring_pipeline : ScoringPipeline | None
        Scoring pipeline opsional untuk menskor meta-alert.
    """

    def __init__(
        self,
        base_delta_t: timedelta = DEFAULT_BASE_DELTA_T,
        adaptive: bool = True,
        reorder_capacity: int = 50,
        scoring_pipeline: Optional[ScoringPipeline] = None,
    ) -> None:
        self.base_delta_t: timedelta = base_delta_t
        self.adaptive: bool = adaptive
        self.reorder_capacity: int = reorder_capacity
        self.scoring_pipeline: Optional[ScoringPipeline] = scoring_pipeline

    def run(self, alerts: Iterable[CanonicalRawAlert]) -> BatchRunResult:
        """Proses raw alert kanonis lewat RBTA, ekstrak fitur, dan skor bila pipeline tersedia.

        Parameters
        ----------
        alerts : Iterable[CanonicalRawAlert]
            Aliran raw alert kanonis.

        Returns
        -------
        BatchRunResult
            Meta-alert hasil agregasi, matriks fitur, dan output skor opsional.
        """
        buffer = LosslessReorderBuffer(capacity=self.reorder_capacity)
        engine = RBTAEngine(base_delta_t=self.base_delta_t, adaptive=self.adaptive)
        finalized_metas: List[MetaAlert] = []

        for alert in alerts:
            ready_alerts = buffer.push(alert)
            for ready in ready_alerts:
                finalized_metas.extend(engine.process(ready))

        # Kuras reorder buffer.
        for ready in buffer.drain():
            finalized_metas.extend(engine.process(ready))

        # Kuras engine RBTA.
        finalized_metas.extend(engine.drain())

        # Ekstrak 7 fitur.
        features_df = SevenFeatureExtractor.extract_features_df(finalized_metas)

        scored_metas: Optional[List[ScoredMetaAlert]] = None
        scored_df: Optional[pd.DataFrame] = None

        if self.scoring_pipeline is not None:
            scored_df, scored_metas = self.scoring_pipeline.score_meta_alerts(finalized_metas)

        return BatchRunResult(
            meta_alerts=finalized_metas,
            features_df=features_df,
            scored_meta_alerts=scored_metas,
            scored_df=scored_df,
        )
