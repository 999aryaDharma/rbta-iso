"""Metrik context purity, agar kesimpulan baseline tidak hanya bersandar pada ARR."""

from dataclasses import dataclass
from typing import Iterable, Sequence

from src.contracts.meta_alert import MetaAlert
from src.contracts.raw_alert import CanonicalRawAlert


@dataclass(frozen=True)
class ContextQualityResult:
    total_meta_alerts: int
    pure_meta_alerts: int
    contaminated_meta_alerts: int
    context_purity_percent: float
    context_contamination_percent: float


def compute_context_quality(
    meta_alerts: Sequence[MetaAlert],
    raw_alerts: Iterable[CanonicalRawAlert],
) -> ContextQualityResult:
    """Ukur apakah setiap meta-alert hanya berisi tepat satu konteks agent/group."""
    source_context = {
        alert.wazuh_alert_id: (alert.agent_id, alert.rule_group_primary)
        for alert in raw_alerts
    }
    pure = 0
    contaminated = 0
    for meta in meta_alerts:
        contexts = set()
        for source_id in meta.wazuh_alert_ids:
            if source_id not in source_context:
                raise ValueError(
                    f"Cannot calculate context purity: missing source alert '{source_id}'"
                )
            contexts.add(source_context[source_id])
        if len(contexts) == 1:
            pure += 1
        else:
            contaminated += 1

    total = len(meta_alerts)
    purity = (pure / total * 100.0) if total else 100.0
    contamination = (contaminated / total * 100.0) if total else 0.0
    return ContextQualityResult(
        total_meta_alerts=total,
        pure_meta_alerts=pure,
        contaminated_meta_alerts=contaminated,
        context_purity_percent=purity,
        context_contamination_percent=contamination,
    )
