"""Orkestrator penelitian kanonis untuk RBTA + Isolation Forest.

Menjalankan pipeline metodologi penelitian end-to-end dengan urutan fase berikut:
Fase 1: Pemuatan & validasi input (JSONL asli atau fixture engineering eksplisit)
Fase 2: Analisis sensitivitas delta-t (adaptive=False)
Fase 3: Pemilihan delta-t dasar (elbow sensitivitas atau override manual)
Fase 4: Agregasi temporal RBTA final (ETW lokal per agent, adaptive=True, delta-t terpilih)
Fase 5: Baseline Fixed Tumbling Window (delta-t terpilih)
Fase 6: Evaluasi ketahanan noise (delta-t terpilih)
Fase 7: Evaluasi kompleksitas runtime (8 subset, delta-t terpilih)
Fase 8: Ekstraksi tujuh fitur kanonis
Fase 9: Training reference Isolation Forest & publikasi model
Fase 10: Scoring anomali yang aman untuk stream & evaluasi Decision Matrix
Fase 11: Silhouette struktural vs baseline 100 permutasi
Fase 12: Publikasi artefak run yang terstruktur
"""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Sequence, Union
import uuid

import numpy as np
import pandas as pd

from src.contracts.raw_alert import CanonicalRawAlert
from src.evaluation.fixed_window_baseline import run_fixed_window_baseline
from src.evaluation.contextual_fixed_baseline import run_contextual_fixed_window_baseline
from src.evaluation.context_quality import compute_context_quality
from src.evaluation.metrics import compute_arr
from src.evaluation.noise_robustness import run_noise_robustness_evaluation
from src.evaluation.runtime_complexity import RUNTIME_EVALUATION_SUBSETS, run_runtime_complexity_evaluation
from src.evaluation.sensitivity import SENSITIVITY_DELTA_T_MINUTES, run_delta_t_sensitivity_analysis
from src.evaluation.structural_silhouette import run_structural_silhouette_evaluation
from src.features.extractor import FEATURE_COLUMNS, SevenFeatureExtractor
from src.model.registry import ModelRegistry
from src.model.scoring_pipeline import (
    ModelArtifactBundle,
    ScoringPipeline,
    train_reference_pipeline,
)
from src.rbta.engine import RBTAEngine
from src.runners.batch_runner import BatchResearchRunner
from src.research.corpus_input import ResearchCorpusError, load_research_corpus


class ResearchInputError(RuntimeError):
    """Dilempar bila input penelitian tidak valid, tidak ada, atau saling bertentangan."""
    pass


def _generate_engineering_smoke_fixture(n_alerts: int = 250, seed: int = 42) -> List[CanonicalRawAlert]:
    """Bangkitkan raw alert sintetis deterministik untuk smoke test dan verifikasi developer.

    CATATAN: fixture ini hanya untuk smoke test engineering dan TIDAK boleh dipakai
    sebagai data penelitian untuk hasil seminar.
    """
    rng = np.random.default_rng(seed)
    base_t = datetime(2026, 8, 28, 8, 0, 0, tzinfo=timezone.utc)
    agents = [("001", "soc-srv1", 3), ("002", "soc-srv2", 2), ("003", "soc-db", 4), ("004", "soc-gw", 1)]
    rule_groups = ["pam", "sshd", "web", "syslog", "firewall", "ids"]

    alerts: List[CanonicalRawAlert] = []
    current_time = base_t

    n_attack = min(30, max(5, n_alerts // 8))
    n_benign = max(1, n_alerts - n_attack)

    # Trafik latar belakang yang benign.
    for i in range(n_benign):
        gap_sec = float(rng.exponential(scale=30.0) + 2.0)
        current_time += timedelta(seconds=gap_sec)

        agent_id, agent_name, agent_crit = agents[int(rng.integers(0, len(agents)))]
        group = rule_groups[int(rng.integers(0, len(rule_groups)))]
        sev = int(rng.integers(1, 6))
        rule_id = f"{int(rng.integers(1000, 5000))}"

        alerts.append(
            CanonicalRawAlert(
                wazuh_alert_id=f"alert_{i+1:05d}",
                timestamp=current_time,
                agent_id=agent_id,
                agent_name=agent_name,
                rule_group_primary=group,
                rule_level=sev,
                rule_id=rule_id,
                mitre_tactics=(),
                srcip=None,
                agent_criticality=agent_crit,
            )
        )

    # Burst serangan anomali yang berat.
    attack_time = current_time + timedelta(minutes=10)
    for j in range(n_attack):
        attack_time += timedelta(seconds=float(rng.uniform(1.0, 5.0)))
        alerts.append(
            CanonicalRawAlert(
                wazuh_alert_id=f"alert_{n_benign + j + 1:05d}",
                timestamp=attack_time,
                agent_id="003",
                agent_name="soc-db",
                rule_group_primary="pam",
                rule_level=14,
                rule_id=f"{9000 + (j % 5)}",
                mitre_tactics=("Initial Access", "Execution", "Privilege Escalation"),
                srcip="10.0.0.99",
                agent_criticality=4,
            )
        )

    return alerts


def build_research_config_payload(
    selected_delta_t_minutes: int,
    random_seed: int,
    model_version: str,
) -> Dict[str, Any]:
    """Susun dict konfigurasi deterministik untuk di-hash."""
    return {
        "selected_delta_t_minutes": selected_delta_t_minutes,
        "adaptive_final": True,
        "ema_alpha": 0.10,
        "warmup_event_count": 100,
        "delta_clamp_lower": 0.5,
        "delta_clamp_upper": 1.5,
        "max_bucket_duration_minutes": 60,
        "feature_schema_version": "1.0",
        "feature_columns": list(FEATURE_COLUMNS),
        "isolation_forest_n_estimators": 200,
        "isolation_forest_contamination": "auto",
        "random_state": random_seed,
        "score_calibration_version": "minmax-v1",
        "threshold_method": "tukey_iqr_1.5",
        "evaluation_seed": random_seed,
        "model_version": model_version,
    }


def compute_research_config_hash(config_payload: Dict[str, Any]) -> str:
    """Turunkan hash SHA-256 deterministik dari payload konfigurasi penelitian."""
    serialized = json.dumps(config_payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def resolve_git_commit(require_git: bool = True) -> str:
    """Ambil SHA commit Git saat ini."""
    try:
        res = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True)
        sha = res.stdout.strip()
        if len(sha) == 40:
            return sha
    except Exception as exc:
        if require_git:
            raise ResearchInputError(f"Failed to resolve mandatory Git commit SHA: {exc}") from exc
    return "0" * 40


def run_canonical_research_pipeline(
    raw_alerts: Optional[Sequence[CanonicalRawAlert]] = None,
    raw_file_path: Optional[Path] = None,
    is_fixture_mode: bool = False,
    output_base_dir: Path = Path("artifacts/research-runs"),
    model_version: str = "rbta-if-canonical-v1",
    delta_t_mode: Union[str, int] = "auto",
    random_seed: int = 42,
    git_commit: Optional[str] = None,
    training_run_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Jalankan pipeline orkestrator penelitian end-to-end sesuai urutan fase."""
    run_id = training_run_id or f"run_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{str(uuid.uuid4())[:8]}"
    run_dir = output_base_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    t_start = time.perf_counter()

    print("=" * 70)
    print("RBTA + ISOLATION FOREST CANONICAL RESEARCH PIPELINE")
    print(f"Run ID        : {run_id}")
    print(f"Output Dir    : {run_dir.resolve()}")
    print(f"Model Version : {model_version}")
    print("=" * 70)

    # Fase 1: ingestion & validasi.
    print("\n[Phase 1] Ingestion & Input Validation...")
    alerts: List[CanonicalRawAlert] = []
    input_mode = "real_jsonl"
    input_provenance = ""
    input_corpus: Optional[Dict[str, Any]] = None
    research_valid = True

    if raw_alerts is not None:
        alerts = list(raw_alerts)
        input_provenance = "in_memory_alerts"
        input_mode = "engineering_fixture" if is_fixture_mode else "real_jsonl"
        research_valid = not is_fixture_mode
    elif raw_file_path is not None:
        try:
            corpus = load_research_corpus(raw_file_path)
        except ResearchCorpusError as exc:
            raise ResearchInputError(str(exc)) from exc
        alerts = corpus.alerts
        input_corpus = corpus.provenance
        input_mode = "real_jsonl"
        input_provenance = str(raw_file_path.resolve())
        research_valid = True
    elif is_fixture_mode:
        print("\n" + "#" * 70)
        print("  *** ENGINEERING SMOKE FIXTURE MODE ***")
        print("  *** NOT REAL RESEARCH DATA — DO NOT USE METRICS AS SEMINAR RESULTS ***")
        print("#" * 70 + "\n")
        alerts = _generate_engineering_smoke_fixture(n_alerts=250, seed=random_seed)
        input_mode = "engineering_fixture"
        input_provenance = "deterministic_engineering_fixture_250"
        research_valid = False
    else:
        raise ResearchInputError(
            "No input source specified. Provide --input <path> for real research logs, "
            "or --fixture for explicit engineering smoke testing."
        )

    dataset_n_raw = len(alerts)
    if dataset_n_raw == 0:
        raise ResearchInputError("Input dataset contains zero valid canonical alerts.")
    sorted_alerts = sorted(alerts, key=lambda alert: alert.timestamp)
    reference_end = int(dataset_n_raw * 0.60)
    calibration_end = reference_end + int(dataset_n_raw * 0.20)
    reference_alerts = sorted_alerts[:reference_end]
    calibration_alerts = sorted_alerts[reference_end:calibration_end]
    test_alerts = sorted_alerts[calibration_end:]
    if min(len(reference_alerts), len(calibration_alerts), len(test_alerts)) < 4:
        raise ResearchInputError(
            "Chronological 60/20/20 evaluation requires at least 4 raw alerts in every partition"
        )
    print(f"  Loaded {dataset_n_raw} canonical raw alerts (input_mode: {input_mode})")
    print(
        "  Chronological split: "
        f"reference={len(reference_alerts)}, calibration={len(calibration_alerts)}, test={len(test_alerts)}"
    )

    # Fase 2: analisis sensitivitas delta-t (adaptive=False).
    print("\n[Phase 2] Delta-t Sensitivity Analysis (adaptive=False)...")
    sens_result = run_delta_t_sensitivity_analysis(reference_alerts)
    recommended_delta_t = sens_result.recommended_elbow_delta_t
    print(f"  Sensitivity Curve Evaluated: {list(SENSITIVITY_DELTA_T_MINUTES)}")
    print(f"  Calculated Recommended Elbow Delta-t: {recommended_delta_t} minutes")

    # Fase 3: pemilihan delta-t dasar.
    print("\n[Phase 3] Delta-t Window Selection...")
    if str(delta_t_mode).lower() == "auto":
        selected_delta_t = recommended_delta_t
        selection_source = "sensitivity_elbow"
        print(f"  Auto-selected Sensitivity Elbow Delta-t: {selected_delta_t} minutes")
    else:
        try:
            selected_delta_t = int(delta_t_mode)
            selection_source = "manual_override"
            print(f"  Manual Experimental Override Delta-t: {selected_delta_t} minutes (Recommended was {recommended_delta_t}m)")
        except ValueError as exc:
            raise ResearchInputError(f"Invalid --delta-t value '{delta_t_mode}'. Use 'auto' or integer minutes.") from exc

    selected_duration = timedelta(minutes=selected_delta_t)

    # Fase 4: agregasi temporal RBTA final (ETW lokal per agent, adaptive=True, delta-t terpilih).
    print(f"\n[Phase 4] Final RBTA Temporal Aggregation (adaptive=True, base_delta_t={selected_delta_t}m)...")
    reference_result = BatchResearchRunner(base_delta_t=selected_duration, adaptive=True).run(reference_alerts)
    calibration_result = BatchResearchRunner(base_delta_t=selected_duration, adaptive=True).run(calibration_alerts)
    test_result = BatchResearchRunner(base_delta_t=selected_duration, adaptive=True).run(test_alerts)
    reference_metas = reference_result.meta_alerts
    calibration_metas = calibration_result.meta_alerts
    meta_alerts = test_result.meta_alerts
    n_raw = len(test_alerts)
    n_meta = len(meta_alerts)
    arr = compute_arr(n_raw, n_meta)
    print(f"  Test MetaAlerts: {n_meta}")
    print(f"  Alert Reduction Rate (ARR): {arr:.2f}%")

    # Fase 5: baseline Fixed Tumbling Window (delta-t terpilih).
    print(f"\n[Phase 5] Fixed Tumbling Window Baseline (duration={selected_delta_t}m)...")
    baseline_result = run_fixed_window_baseline(test_alerts, window_duration=selected_duration)
    contextual_fixed_result = run_contextual_fixed_window_baseline(
        test_alerts,
        window_duration=selected_duration,
    )
    time_quality = compute_context_quality(baseline_result.meta_alerts, test_alerts)
    contextual_fixed_quality = compute_context_quality(contextual_fixed_result.meta_alerts, test_alerts)
    rbta_quality = compute_context_quality(meta_alerts, test_alerts)
    print(f"  Fixed Window Baseline ARR: {baseline_result.arr:.2f}% (RBTA ARR: {arr:.2f}%)")

    # Fase 6: evaluasi ketahanan noise (delta-t terpilih).
    print(f"\n[Phase 6] Noise Robustness Evaluation (delta_t={selected_delta_t}m)...")
    noise_result = run_noise_robustness_evaluation(test_alerts, delta_t=selected_duration, random_seed=random_seed)

    # Fase 7: kompleksitas runtime (delta-t terpilih, tepat 8 subset).
    print(f"\n[Phase 7] Runtime Complexity Evaluation (8 subsets, delta_t={selected_delta_t}m)...")
    complexity_result = run_runtime_complexity_evaluation(test_alerts, n_subsets=RUNTIME_EVALUATION_SUBSETS, delta_t=selected_duration)
    print(f"  Empirical runtime scaling R^2: {complexity_result.r_squared:.4f} (Slope: {complexity_result.slope:.6f} ms/alert)")

    phase_a_summary = {
        "rbta_arr": arr,
        "fixed_baseline_arr": baseline_result.arr,
        "contextual_fixed_arr": contextual_fixed_result.arr,
        "arr_advantage_percent_points": round(arr - contextual_fixed_result.arr, 2),
        "aggregation_ablation": [
            {
                "variant": "time_only_fixed",
                "n_raw": baseline_result.n_raw,
                "n_meta": baseline_result.n_meta,
                "arr": baseline_result.arr,
                "context_purity_percent": time_quality.context_purity_percent,
                "context_contamination_percent": time_quality.context_contamination_percent,
            },
            {
                "variant": "contextual_fixed",
                "n_raw": contextual_fixed_result.n_raw,
                "n_meta": contextual_fixed_result.n_meta,
                "arr": contextual_fixed_result.arr,
                "context_purity_percent": contextual_fixed_quality.context_purity_percent,
                "context_contamination_percent": contextual_fixed_quality.context_contamination_percent,
            },
            {
                "variant": "contextual_adaptive",
                "n_raw": n_raw,
                "n_meta": n_meta,
                "arr": arr,
                "context_purity_percent": rbta_quality.context_purity_percent,
                "context_contamination_percent": rbta_quality.context_contamination_percent,
            },
        ],
        "recommended_elbow_delta_t_minutes": recommended_delta_t,
        "selected_delta_t_minutes": selected_delta_t,
        "delta_t_selection_source": selection_source,
        "runtime_r_squared": complexity_result.r_squared,
        "mean_throughput_alerts_per_ms": complexity_result.mean_throughput,
        "runtime_repetitions": complexity_result.repetitions,
        "runtime_preparation_time_ms": complexity_result.preparation_time_ms,
        "sensitivity_curve": sens_result.summary_df.to_dict(orient="records"),
        "noise_robustness": noise_result.summary_df.to_dict(orient="records"),
        "complexity_subsets": complexity_result.subset_df.to_dict(orient="records"),
    }
    with (run_dir / "phase_a_results.json").open("w", encoding="utf-8") as f:
        json.dump(phase_a_summary, f, indent=2)

    # Fase 8: ekstraksi tujuh fitur kanonis (dari meta_alerts dengan delta-t terpilih).
    print("\n[Phase 8] Seven Canonical Feature Extraction...")
    df_features = SevenFeatureExtractor.extract_features_df(meta_alerts)
    print(f"  Extracted feature matrix shape: {df_features.shape}")
    print(f"  Feature columns: {list(FEATURE_COLUMNS)}")

    # Fase 9: training reference Isolation Forest & publikasi model.
    print("\n[Phase 9] Isolation Forest Model Training & Artifact Publication...")
    config_payload = build_research_config_payload(selected_delta_t, random_seed, model_version)
    config_hash = compute_research_config_hash(config_payload)
    resolved_git_commit = git_commit or resolve_git_commit(require_git=research_valid)

    bundle = train_reference_pipeline(
        reference_metas,
        calibration_metas=calibration_metas,
        random_state=random_seed,
        model_version=model_version,
        training_run_id=run_id,
        git_commit=resolved_git_commit,
        research_config_hash=config_hash,
    )
    models_dir = run_dir / "models"
    registry = ModelRegistry(base_dir=models_dir, explicit_version=model_version)
    published_dir = registry.publish_bundle(bundle, model_version=model_version)
    print(f"  Published model bundle to: {published_dir}")
    print(f"  Tukey Threshold (theta)  : {bundle.threshold.threshold:.4f} (Q3={bundle.threshold.q3:.4f}, IQR={bundle.threshold.iqr:.4f})")

    # Fase 10: scoring anomali yang aman untuk stream & evaluasi Decision Matrix.
    print("\n[Phase 10] Anomaly Scoring & Decision Matrix Evaluation...")
    pipeline = ScoringPipeline(bundle)
    df_scored, scored_meta_alerts = pipeline.score_meta_alerts(meta_alerts)
    scored_csv_path = run_dir / "meta_alerts_scored.csv"
    df_scored.to_csv(scored_csv_path, index=False)
    print(f"  Scored results exported to: {scored_csv_path}")

    # Fase 11: Silhouette struktural vs permutasi.
    print("\n[Phase 11] Phase B Structural Silhouette vs 100 Permutations...")
    silhouette_result = run_structural_silhouette_evaluation(
        scored_meta_alerts, bundle, n_permutations=100, random_seed=random_seed
    )
    phase_b_summary = {
        "evaluation_population": "test_without_refit",
        "is_calculable": silhouette_result.is_calculable,
        "uncalculable_reason": silhouette_result.uncalculable_reason,
        "observed_silhouette": silhouette_result.observed_silhouette,
        "null_distribution_mean": silhouette_result.random_mean,
        "null_distribution_std": silhouette_result.random_std,
        "null_distribution_min": silhouette_result.random_min,
        "null_distribution_max": silhouette_result.random_max,
        "observed_percentile": silhouette_result.observed_percentile,
        "z_score": silhouette_result.z_score,
        "empirical_p_value": silhouette_result.empirical_p_value,
        "n_permutations": silhouette_result.n_valid_permutations,
    }
    with (run_dir / "phase_b_results.json").open("w", encoding="utf-8") as f:
        json.dump(phase_b_summary, f, indent=2)

    if silhouette_result.is_calculable:
        print(f"  Observed Silhouette Score : {silhouette_result.observed_silhouette:.4f}")
        print(f"  Null Distribution Mean    : {silhouette_result.random_mean:.4f} +/- {silhouette_result.random_std:.4f}")
        print(f"  Standardized Z-Score      : {silhouette_result.z_score:.2f}")
        print(f"  Empirical p-value         : {silhouette_result.empirical_p_value:.4f}")
    else:
        print(f"  Silhouette evaluation not calculable: {silhouette_result.uncalculable_reason}")

    # Fase 12: publikasi artefak run yang terstruktur.
    elapsed_total = time.perf_counter() - t_start
    manifest = {
        "run_id": run_id,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed_total, 3),
        "git_commit": resolved_git_commit,
        "input_mode": input_mode,
        "input_provenance": input_provenance,
        "input_corpus": input_corpus,
        "research_results_valid_for_seminar": research_valid,
        "random_seed": random_seed,
        "sensitivity_delta_values": list(SENSITIVITY_DELTA_T_MINUTES),
        "recommended_delta_t_minutes": recommended_delta_t,
        "selected_delta_t_minutes": selected_delta_t,
        "delta_t_selection_source": selection_source,
        "adaptive_final": True,
        "ema_alpha": 0.10,
        "warmup_count": 100,
        "n_raw_alerts": dataset_n_raw,
        "evaluation_n_raw_alerts": n_raw,
        "n_meta_alerts": n_meta,
        "arr": arr,
        "fixed_window_duration_minutes": selected_delta_t,
        "fixed_window_arr": baseline_result.arr,
        "noise_rates": list(noise_result.summary_df["noise_rate"]),
        "runtime_subset_count": RUNTIME_EVALUATION_SUBSETS,
        "runtime_repetitions": complexity_result.repetitions,
        "temporal_split": {
            "strategy": "chronological",
            "reference": {
                "n_raw": len(reference_alerts),
                "n_meta": len(reference_metas),
                "start": reference_alerts[0].timestamp.isoformat(),
                "end": reference_alerts[-1].timestamp.isoformat(),
            },
            "calibration": {
                "n_raw": len(calibration_alerts),
                "n_meta": len(calibration_metas),
                "start": calibration_alerts[0].timestamp.isoformat(),
                "end": calibration_alerts[-1].timestamp.isoformat(),
            },
            "test": {
                "n_raw": len(test_alerts),
                "n_meta": len(meta_alerts),
                "start": test_alerts[0].timestamp.isoformat(),
                "end": test_alerts[-1].timestamp.isoformat(),
            },
        },
        "model_version": model_version,
        "training_run_id": run_id,
        "feature_schema_version": "1.0",
        "research_config_hash": config_hash,
        "n_permutations": silhouette_result.n_valid_permutations,
        "published_artifacts": {
            "phase_a_results": "phase_a_results.json",
            "phase_b_results": "phase_b_results.json",
            "meta_alerts_scored": "meta_alerts_scored.csv",
            "research_summary": "research_summary.json",
        },
    }
    with (run_dir / "run_manifest.json").open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    with (run_dir / "research_config.json").open("w", encoding="utf-8") as f:
        json.dump(config_payload, f, indent=2)

    research_summary = {
        "manifest": manifest,
        "research_config": config_payload,
        "phase_a": phase_a_summary,
        "phase_b": phase_b_summary,
    }
    with (run_dir / "research_summary.json").open("w", encoding="utf-8") as f:
        json.dump(research_summary, f, indent=2)

    print("\n" + "=" * 70)
    print(f"CANONICAL RESEARCH PIPELINE COMPLETED IN {elapsed_total:.2f}s")
    print(f"All artifacts published to: {run_dir.resolve()}")
    print("=" * 70)

    return research_summary


def build_argument_parser() -> argparse.ArgumentParser:
    """Susun argument parser CLI penelitian."""
    parser = argparse.ArgumentParser(
        description="RBTA + Isolation Forest Canonical Research Orchestrator",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--input",
        type=Path,
        default=None,
        help="Path to one Wazuh .jsonl/.jsonl.gz file or a directory of daily exports",
    )
    group.add_argument("--fixture", action="store_true", help="Run explicit engineering smoke fixture (non-seminar)")

    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/research-runs"), help="Output directory")
    parser.add_argument("--model-version", type=str, default="rbta-if-canonical-v1", help="Model version identifier")
    parser.add_argument("--delta-t", type=str, default="auto", help="Base Delta-t window in minutes ('auto' or integer)")
    parser.add_argument("--seed", type=int, default=42, help="Deterministic random seed")

    return parser


def main(argv: Optional[Sequence[str]] = None) -> None:
    """Entrypoint CLI untuk menjalankan orkestrator penelitian."""
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    run_canonical_research_pipeline(
        raw_file_path=args.input,
        is_fixture_mode=args.fixture,
        output_base_dir=args.output_dir,
        model_version=args.model_version,
        delta_t_mode=args.delta_t,
        random_seed=args.seed,
    )


if __name__ == "__main__":
    main()
