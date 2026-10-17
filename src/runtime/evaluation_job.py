"""Evaluasi pasca-replay di latar belakang dengan artefak per run yang atomik."""

from datetime import timedelta
import json
from pathlib import Path
import threading
from typing import Any, Callable, Dict, Optional, Sequence, Union

import numpy as np

from src.contracts.raw_alert import CanonicalRawAlert
from src.evaluation.context_quality import compute_context_quality
from src.evaluation.contextual_fixed_baseline import run_contextual_fixed_window_baseline
from src.evaluation.fixed_window_baseline import run_fixed_window_baseline
from src.evaluation.metrics import compute_arr
from src.evaluation.noise_robustness import run_noise_robustness_evaluation
from src.evaluation.runtime_complexity import run_runtime_complexity_evaluation
from src.evaluation.sensitivity import run_delta_t_sensitivity_analysis
from src.evaluation.structural_silhouette import run_structural_silhouette_evaluation
from src.model.scoring_pipeline import ScoringPipeline
from src.runners.batch_runner import BatchResearchRunner
from src.runtime.json_safe import to_json_safe


class EvaluationJobController:
    """Jalankan evaluasi penelitian lengkap setelah replay tanpa memblokir polling API."""

    TOTAL_PHASES = 7

    def __init__(self, scoring_pipeline: ScoringPipeline) -> None:
        self.scoring_pipeline = scoring_pipeline
        self._lock = threading.RLock()
        self._cancel_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.run_id: Optional[str] = None
        self.status = "IDLE"
        self.current_phase: Optional[str] = None
        self.completed_phases = 0
        self.results: Dict[str, Any] = {}
        self.last_error: Optional[Dict[str, str]] = None
        self.artifact_path: Optional[Path] = None

    def _snapshot(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "status": self.status,
            "current_phase": self.current_phase,
            "completed_phases": self.completed_phases,
            "total_phases": self.TOTAL_PHASES,
            "progress_percent": round(self.completed_phases / self.TOTAL_PHASES * 100.0, 2),
            "results": to_json_safe(self.results),
            "last_error": self.last_error,
            "artifact_available": bool(
                self.artifact_path and self.artifact_path.is_file() and self.status == "COMPLETED"
            ),
        }

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            return self._snapshot()

    def _complete_phase(self, name: str, result_key: str, result: Any) -> None:
        with self._lock:
            self.current_phase = name
            self.results[result_key] = to_json_safe(result)
            self.completed_phases += 1

    def _check_cancelled(self) -> None:
        if self._cancel_event.is_set():
            raise InterruptedError("Evaluation cancelled by operator")

    def start(
        self,
        run_id: str,
        alerts: Sequence[CanonicalRawAlert],
        artifact_path: Union[str, Path],
        base_delta_t: timedelta = timedelta(minutes=15),
        random_seed: int = 42,
    ) -> Dict[str, Any]:
        with self._lock:
            if self.status == "RUNNING":
                raise RuntimeError("An evaluation job is already running")
            if len(alerts) < 4:
                raise ValueError("Post-replay evaluation requires at least 4 canonical alerts")
            self.run_id = run_id
            self.status = "RUNNING"
            self.current_phase = "queued"
            self.completed_phases = 0
            self.results = {}
            self.last_error = None
            self.artifact_path = Path(artifact_path).resolve()
            self._cancel_event.clear()
            self._thread = threading.Thread(
                target=self._run,
                args=(list(alerts), base_delta_t, random_seed),
                daemon=True,
                name=f"evaluation-{run_id[:8]}",
            )
            self._thread.start()
            return self._snapshot()

    def cancel(self) -> Dict[str, Any]:
        with self._lock:
            if self.status == "RUNNING":
                self._cancel_event.set()
            return self._snapshot()

    def wait_until_complete(self, timeout: float = 30.0) -> Dict[str, Any]:
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=timeout)
        return self.get_status()

    def _run(self, alerts: Sequence[CanonicalRawAlert], delta_t: timedelta, seed: int) -> None:
        try:
            self.current_phase = "delta_t_sensitivity"
            sensitivity = run_delta_t_sensitivity_analysis(alerts)
            self._complete_phase(
                "delta_t_sensitivity",
                "sensitivity",
                sensitivity.summary_df.to_dict(orient="records"),
            )
            self.results["recommended_elbow_delta_t_minutes"] = sensitivity.recommended_elbow_delta_t
            self._check_cancelled()

            self.current_phase = "aggregation_ablation"
            time_only = run_fixed_window_baseline(alerts, delta_t)
            contextual_fixed = run_contextual_fixed_window_baseline(alerts, delta_t)
            adaptive = BatchResearchRunner(base_delta_t=delta_t, adaptive=True).run(alerts)
            variants = (
                ("time_only_fixed", time_only.meta_alerts),
                ("contextual_fixed", contextual_fixed.meta_alerts),
                ("contextual_adaptive", adaptive.meta_alerts),
            )
            ablation = []
            for name, metas in variants:
                quality = compute_context_quality(metas, alerts)
                ablation.append({
                    "variant": name,
                    "n_raw": len(alerts),
                    "n_meta": len(metas),
                    "arr": compute_arr(len(alerts), len(metas)),
                    "context_purity_percent": quality.context_purity_percent,
                    "context_contamination_percent": quality.context_contamination_percent,
                })
            self._complete_phase("aggregation_ablation", "aggregation_ablation", ablation)
            self._check_cancelled()

            self.current_phase = "noise_robustness"
            noise = run_noise_robustness_evaluation(alerts, delta_t=delta_t, random_seed=seed)
            self._complete_phase(
                "noise_robustness",
                "noise_robustness",
                noise.summary_df.to_dict(orient="records"),
            )
            self._check_cancelled()

            self.current_phase = "runtime_complexity"
            runtime = run_runtime_complexity_evaluation(alerts, delta_t=delta_t, repetitions=5)
            self._complete_phase(
                "runtime_complexity",
                "runtime",
                {
                    "subsets": runtime.subset_df.to_dict(orient="records"),
                    "slope_ms_per_alert": runtime.slope,
                    "intercept_ms": runtime.intercept,
                    "r_squared": runtime.r_squared,
                    "mean_throughput_alerts_per_ms": runtime.mean_throughput,
                    "throughput_variation": runtime.throughput_variation,
                    "repetitions": runtime.repetitions,
                    "preparation_time_ms": runtime.preparation_time_ms,
                },
            )
            self._check_cancelled()

            self.current_phase = "frozen_model_scoring"
            scored = self.scoring_pipeline.score_batch(adaptive.meta_alerts)
            scores = [float(item.anomaly_score) for item in scored]
            decision_counts = {name: 0 for name in ("CRITICAL", "SUSPICIOUS", "NOISE_HIGH", "NOISE")}
            action_counts = {name: 0 for name in ("ESCALATE", "DAILY_DIGEST", "SUPPRESS")}
            for item in scored:
                decision_counts[item.decision] = decision_counts.get(item.decision, 0) + 1
                action_counts[item.action] = action_counts.get(item.action, 0) + 1
            model_result = {
                "evaluation_population": "frozen_model_replay",
                "refit_performed": False,
                "model_version": self.scoring_pipeline.metadata.get("model_version"),
                "training_run_id": self.scoring_pipeline.metadata.get("training_run_id"),
                "validation_strategy": self.scoring_pipeline.metadata.get("validation_strategy"),
                "meta_alert_count": len(scored),
                "score_min": min(scores) if scores else None,
                "score_max": max(scores) if scores else None,
                "score_mean": float(np.mean(scores)) if scores else None,
                "decision_distribution": decision_counts,
                "action_distribution": action_counts,
            }
            self._complete_phase("frozen_model_scoring", "isolation_forest", model_result)
            self._check_cancelled()

            self.current_phase = "structural_silhouette"
            structural = run_structural_silhouette_evaluation(
                scored,
                self.scoring_pipeline.bundle,
                n_permutations=100,
                random_seed=seed,
            )
            self._complete_phase("structural_silhouette", "structural_silhouette", structural.__dict__)
            self._check_cancelled()

            interpretation = {
                "attack_detection_accuracy_available": False,
                "arr": "Pengurangan unit triase; bukan akurasi deteksi.",
                "context_purity": "Kemurnian konteks agent dan rule group dalam setiap meta-alert.",
                "silhouette": "Pemisahan struktural internal dibanding partisi acak berproporsi sama.",
                "external_integrations": "Wazuh live, Shuffle, dan Telegram eksternal tidak diuji oleh job ini.",
            }
            self._complete_phase("artifact_publication", "interpretation", interpretation)

            assert self.artifact_path is not None
            self.artifact_path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "schema_version": "1.0",
                "run_id": self.run_id,
                "random_seed": seed,
                "results": to_json_safe(self.results),
            }
            tmp_path = self.artifact_path.with_suffix(self.artifact_path.suffix + ".tmp")
            tmp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            tmp_path.replace(self.artifact_path)
            with self._lock:
                self.status = "COMPLETED"
                self.current_phase = "completed"
        except InterruptedError as exc:
            with self._lock:
                self.status = "CANCELLED"
                self.current_phase = "cancelled"
                self.last_error = {"type": type(exc).__name__, "message": str(exc)}
        except Exception as exc:
            with self._lock:
                self.status = "ERROR"
                self.last_error = {"type": type(exc).__name__, "message": str(exc)}
