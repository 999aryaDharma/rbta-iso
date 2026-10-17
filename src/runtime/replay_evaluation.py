"""Metrik penelitian live dengan biaya konstan untuk replay run yang aktif."""

from typing import Any, Dict, Mapping

from src.contracts.scored_meta_alert import ScoredMetaAlert


class ReplayEvaluationTracker:
    """Lacak reduksi live dan perilaku model beku tanpa refit sama sekali."""

    _DECISIONS = ("CRITICAL", "SUSPICIOUS", "NOISE_HIGH", "NOISE")
    _ACTIONS = ("ESCALATE", "DAILY_DIGEST", "SUPPRESS")

    def __init__(self, model_metadata: Mapping[str, Any]) -> None:
        self.model_metadata = dict(model_metadata)
        self.raw_count = 0
        self.finalized_count = 0
        self.source_reference_count = 0
        self.above_threshold_count = 0
        self.reference_range_exceedance_count = 0
        self.decision_counts = {name: 0 for name in self._DECISIONS}
        self.action_counts = {name: 0 for name in self._ACTIONS}
        self.score_count = 0
        self.score_sum = 0.0
        self.score_min = None
        self.score_max = None
        self.histogram = [0, 0, 0, 0, 0, 0]

    def record_raw(self, count: int = 1) -> None:
        if count < 0:
            raise ValueError("Raw count increment cannot be negative")
        self.raw_count += count

    def _histogram_index(self, score: float) -> int:
        if score < 0.0:
            return 0
        if score < 0.25:
            return 1
        if score < 0.5:
            return 2
        if score < 0.75:
            return 3
        if score <= 1.0:
            return 4
        return 5

    def record_scored(self, scored: ScoredMetaAlert) -> None:
        score = float(scored.anomaly_score)
        self.finalized_count += 1
        self.source_reference_count += len(scored.source_alert_ids)
        self.score_count += 1
        self.score_sum += score
        self.score_min = score if self.score_min is None else min(self.score_min, score)
        self.score_max = score if self.score_max is None else max(self.score_max, score)
        self.histogram[self._histogram_index(score)] += 1
        if score >= float(scored.threshold_used):
            self.above_threshold_count += 1
        if score < 0.0 or score > 1.0:
            self.reference_range_exceedance_count += 1
        if scored.decision in self.decision_counts:
            self.decision_counts[scored.decision] += 1
        if scored.action in self.action_counts:
            self.action_counts[scored.action] += 1

    def snapshot(self, *, active_buckets: int, evidence_count: int) -> Dict[str, Any]:
        triage_units = self.finalized_count + active_buckets
        arr = (
            max(0.0, (self.raw_count - triage_units) / self.raw_count * 100.0)
            if self.raw_count
            else 0.0
        )
        threshold_rate = (
            self.above_threshold_count / self.score_count * 100.0
            if self.score_count
            else 0.0
        )
        evidence_coverage = (
            min(100.0, evidence_count / self.raw_count * 100.0)
            if self.raw_count
            else 100.0
        )
        source_coverage = (
            min(100.0, self.source_reference_count / self.raw_count * 100.0)
            if self.raw_count
            else 100.0
        )
        provenance_keys = (
            "model_version", "training_run_id", "training_period_start",
            "training_period_end", "calibration_period_start",
            "calibration_period_end", "validation_strategy", "git_commit",
            "random_state", "contamination",
        )
        return {
            "schema_version": "1.0",
            "raw_alerts": self.raw_count,
            "finalized_meta_alerts": self.finalized_count,
            "active_meta_alerts": active_buckets,
            "triage_units_current": triage_units,
            "live_arr_percent": round(arr, 4),
            "decision_distribution": dict(self.decision_counts),
            "action_distribution": dict(self.action_counts),
            "threshold": {
                "above_count": self.above_threshold_count,
                "above_rate_percent": round(threshold_rate, 4),
            },
            "score_distribution": {
                "count": self.score_count,
                "min": self.score_min,
                "max": self.score_max,
                "mean": (self.score_sum / self.score_count) if self.score_count else None,
                "bins": ["<0", "0–<0.25", "0.25–<0.5", "0.5–<0.75", "0.75–1", ">1"],
                "histogram": list(self.histogram),
            },
            "reference_range_exceedance_count": self.reference_range_exceedance_count,
            "evidence_coverage_percent": round(evidence_coverage, 4),
            "source_reference_coverage_percent": round(source_coverage, 4),
            "model_provenance": {
                key: self.model_metadata.get(key)
                for key in provenance_keys
                if key in self.model_metadata
            },
            "claim_boundary": {
                "accuracy_available": False,
                "arr_interpretation": "ARR mengukur pengurangan unit triase, bukan akurasi deteksi serangan.",
                "score_interpretation": "Isolation Forest memberi skor keanehan untuk prioritas, bukan label serangan.",
                "silhouette_interpretation": "Silhouette adalah evaluasi struktural internal, bukan bukti akurasi serangan.",
                "contamination_interpretation": "contamination='auto' tidak menentukan eskalasi; Tukey dan decision matrix yang digunakan.",
            },
        }
