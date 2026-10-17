"""
main.py  —  Pipeline Orchestrator RBTA (Landauer et al. 2022 alignment)
=======================================================================
Urutan eksekusi mengikuti struktur evaluasi Landauer et al. (2022):

  STEP 1  Preprocessing          → load_and_prepare()
  STEP 2  [opsional] Injection   → attack_injector.run_injection()
  STEP 3  Sensitivity Analysis   → metrics.sensitivity_analysis()
                                   [Landauer Section 6.3]
  STEP 4  RBTA optimal Δt        → rbta_core.run_rbta()
                                   [Landauer Section 6.4-6.5]
  STEP 5  Feature Engineering    → add_if_features() + enrich_features()
  STEP 6  [opsional] Labels      → attack_injector.propagate_labels()
  STEP 7  Fixed Window Baseline  → fixed_window_baseline.run_fixed_window()
  STEP 8  ARR per Rule Group     → metrics.compute_arr_per_group()
                                   [Landauer Section 6.8]
  STEP 9  Isolation Forest       → isolation_forest.run_pipeline()
  STEP 10 FPR vs Reduction       → metrics.compute_fpr_vs_reduction()
                                   [Landauer Figure 12]
  STEP 11 Noise Robustness Test  → robustness.noise_robustness_test()
                                   [Landauer Section 6.9]
  STEP 12 Runtime Proof O(n)     → metrics.runtime_complexity_proof()
                                   [Landauer Section 6.10]
  STEP 13a Scenario A: RBTA Eval → scenario_a_rbta_evaluation()
  STEP 13b Scenario B: IF Eval   → scenario_b_if_evaluation()
  STEP 14 Detail Plots           → severity dist, alert count dist, dll.
"""

import gc
import logging
import os
import sys
import time
import traceback
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# Path setup
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd

# Imports
from src.etl.preprocessing_01       import load_and_prepare
from src.engine.rbta_core           import run_rbta, validate_mapping, add_if_features
from src.engine.fixed_window_baseline import run_fixed_window
from src.engine.feature_engineering  import enrich_features
from src.engine.isolation_forest     import run_pipeline as run_isolation_forest
from src.evaluation.attack_injector  import run_injection, propagate_labels
from src.evaluation.robustness       import (
    noise_robustness_test, plot_robustness, print_robustness_table,
)
from src.evaluation.metrics          import (
    sensitivity_analysis, find_elbow,
    print_sensitivity_table, print_enhancement_report,
    plot_sensitivity, plot_severity_dist, plot_alert_count_dist,
    plot_watermark_stats, plot_elastic_dt_history,
    compute_arr_per_group, plot_arr_per_group, print_arr_per_group,
    compute_fpr_vs_reduction, plot_fpr_vs_reduction,
    runtime_complexity_proof, plot_runtime_proof,
    compute_pr_auc, plot_pr_curve,
    scenario_a_rbta_evaluation,
    scenario_b_if_evaluation,
    comprehensive_report,
    DELTA_T_VALUES, BUFFER_SIZE, MAX_LATENESS_SEC,
)

# Konfigurasi
RAW_CSV_PATH      = "data/raw/rbta_ready_ALL.csv"
INJECTED_CSV_PATH = "data/injected/rbta_injected.csv"
AGG_DIR           = "data/aggregated"
FINAL_DIR         = "data/final"
FIGURES_DIR       = "reports/figures"
QUALITY_DIR       = "reports/data_quality"

USE_INJECTED_DATA   = True  # True untuk evaluasi PR-AUC/FNR dengan ground truth
INJECTION_SCENARIOS = ["A", "B", "C"]
SKIP_F13            = True  # True untuk melewati f13 (cross_agent_spread) yang O(n²)

# Konfigurasi robustness test (Landauer Section 6.9)
RUN_ROBUSTNESS_TEST = True
NOISE_RATES         = [0.0, 0.05, 0.10, 0.20, 0.30]

# Konfigurasi runtime proof (Landauer Section 6.10)
RUN_RUNTIME_PROOF = True


# Helpers

def safe_step(name: str, fn, *args, **kwargs):
    log.info("=" * 70)
    log.info("  %s", name)
    log.info("=" * 70)
    try:
        result = fn(*args, **kwargs)
        log.info("[OK] %s selesai.", name)
        return result
    except Exception as exc:
        log.error("[ERROR] %s gagal: %s", name, exc)
        traceback.print_exc()
        return None


def _make_dirs():
    for d in [AGG_DIR, FINAL_DIR, FIGURES_DIR, QUALITY_DIR]:
        os.makedirs(d, exist_ok=True)


# Main Pipeline

def main() -> None:
    t_global = time.perf_counter()
    _make_dirs()

    log.info("#" * 70)
    log.info("  RBTA PIPELINE — Landauer et al. (2022) alignment")
    log.info("  INSTIKI SOC Alert Fatigue Research")
    log.info("#" * 70)

    # STEP 1: Preprocessing
    df_raw_original = safe_step(
        "STEP 1 — PREPROCESSING",
        load_and_prepare,
        RAW_CSV_PATH,
    )
    if df_raw_original is None:
        log.error("Preprocessing gagal. Pipeline dihentikan.")
        return

    # STEP 2: [opsional] Attack Injection
    df_raw_injected = None

    if USE_INJECTED_DATA:
        injection_result = safe_step(
            "STEP 2 — ATTACK INJECTION (scenarios: %s)" % INJECTION_SCENARIOS,
            run_injection,
            input_path  = RAW_CSV_PATH,
            output_path = INJECTED_CSV_PATH,
            scenarios   = INJECTION_SCENARIOS,
        )
        if injection_result is not None:
            # Preprocessing pada data injected
            from src.etl.preprocessing_01 import REQUIRED_COLS, OPTIONAL_COLS
            all_cols = {**REQUIRED_COLS, **OPTIONAL_COLS}
            available = {k: v for k, v in all_cols.items() if k in injection_result.columns}
            selected  = [c for c in available.keys() if c in injection_result.columns]
            df_raw_injected = injection_result[selected].rename(columns=available).copy()
            
            # [FIX-1] Preserve kolom kritis untuk label propagation dan traceability
            # wazuh_alert_id: diperlukan untuk propagate_labels (set intersection)
            # is_synthetic: ground truth label
            # scenario_id: scenario attribution
            for col in ["wazuh_alert_id", "is_synthetic", "scenario_id"]:
                if col in injection_result.columns:
                    df_raw_injected[col] = injection_result[col].values
                    log.info("[FIX-1] Kolom %s dipreserve (%d values)", col, len(df_raw_injected[col]))
            
            df_raw_injected["timestamp"] = pd.to_datetime(
                df_raw_injected["timestamp"], errors="coerce", utc=True
            ).dt.tz_localize(None)
            log.info("Dataset injected siap: %d baris", len(df_raw_injected))
    else:
        log.info("STEP 2 — SKIP (USE_INJECTED_DATA=False)")

    # Dataset pipeline utama
    df_pipeline = df_raw_injected if df_raw_injected is not None else df_raw_original

    # STEP 3: Sensitivity Analysis (Landauer Section 6.3)
    sens_result = safe_step(
        "STEP 3 — SENSITIVITY ANALYSIS [Landauer Section 6.3]",
        sensitivity_analysis,
        df_pipeline, DELTA_T_VALUES,
        buffer_size=BUFFER_SIZE, max_lateness_sec=MAX_LATENESS_SEC,
    )

    optimal_dt = 15  # fallback
    df_sens, meta_map, elastic_map, wmark_map = pd.DataFrame(), {}, {}, {}

    if sens_result is not None:
        df_sens, meta_map, elastic_map, wmark_map = sens_result
        optimal_dt = find_elbow(df_sens)
        print_sensitivity_table(df_sens)
        df_sens.to_csv(f"{QUALITY_DIR}/sensitivity_results.csv", index=False)
        safe_step("  PLOT: Sensitivity", plot_sensitivity, df_sens, FIGURES_DIR)

    log.info("Δt optimal = %d menit", optimal_dt)

    # STEP 4: RBTA dengan Δt optimal (Landauer Section 6.4-6.5)
    rbta_result = safe_step(
        f"STEP 4 — RBTA (Δt={optimal_dt} menit) [Landauer Section 6.4-6.5]",
        run_rbta,
        df_pipeline,
        delta_t_minutes  = optimal_dt,
        buffer_size      = BUFFER_SIZE,
        max_lateness_sec = MAX_LATENESS_SEC,
        enable_adaptive  = False,
    )

    df_meta_rbta = None
    idx_map_rbta, elastic_rbta, wmark_rbta = {}, None, None

    if rbta_result is not None:
        df_meta_rbta, df_compound, idx_map_rbta, elastic_rbta, wmark_rbta = rbta_result
        safe_step("  VALIDATE", validate_mapping, df_pipeline, df_meta_rbta, idx_map_rbta)

        if not df_compound.empty:
            df_compound.to_csv(f"{AGG_DIR}/meta_alerts_compound.csv", index=False)

        # STEP 5: Feature Engineering
        for step_name, fn, kwargs in [
            ("f1-f9", add_if_features, {}),
            ("f10-f11", enrich_features, {}),  # [FIX-2] v2: hanya f11 deviation, skip_f13 default=True
        ]:
            r = safe_step(f"STEP 5 — {step_name}", fn, df_meta_rbta, **kwargs)
            if r is not None:
                df_meta_rbta = r

        # STEP 6: [opsional] Label Propagation
        if USE_INJECTED_DATA and df_raw_injected is not None:
            r = safe_step(
                "STEP 6 — LABEL PROPAGATION",
                propagate_labels,
                df_meta_rbta, df_raw_injected, idx_map_rbta,
            )
            if r is not None:
                df_meta_rbta = r
        else:
            log.info("STEP 6 — SKIP")

        df_meta_rbta.to_csv(f"{AGG_DIR}/meta_alerts_rbta.csv", index=False)
        log.info("Meta-alerts RBTA disimpan: %s/meta_alerts_rbta.csv", AGG_DIR)

    # STEP 7: Fixed Window Baseline
    df_meta_fixed  = None
    fixed_result   = safe_step(
        f"STEP 7 — FIXED WINDOW BASELINE (Δt={optimal_dt} menit)",
        run_fixed_window, df_pipeline, delta_t_minutes=optimal_dt,
    )
    if fixed_result is not None:
        df_meta_fixed, _ = fixed_result
        if not df_meta_fixed.empty:
            df_meta_fixed.to_csv(f"{AGG_DIR}/meta_alerts_fixed_window.csv", index=False)

    # STEP 8: ARR per Rule Group (Landauer Section 6.8)
    df_per_group = None
    if df_meta_rbta is not None and not df_meta_rbta.empty:
        df_per_group = safe_step(
            "STEP 8 — ARR PER RULE GROUP [Landauer Section 6.8]",
            compute_arr_per_group,
            df_pipeline, df_meta_rbta, df_meta_fixed,
        )
        if df_per_group is not None:
            print_arr_per_group(df_per_group)
            df_per_group.to_csv(f"{QUALITY_DIR}/arr_per_rule_group.csv", index=False)
            safe_step("  PLOT: ARR per Group",
                      plot_arr_per_group, df_per_group, FIGURES_DIR)

    # STEP 9: Isolation Forest
    df_scored = None
    rbta_csv  = f"{AGG_DIR}/meta_alerts_rbta.csv"

    if os.path.exists(rbta_csv):
        if_result = safe_step(
            "STEP 9 — ISOLATION FOREST",
            run_isolation_forest,
            rbta_csv, FINAL_DIR, "auto", 200, "iqr", None, 42,
        )
        if if_result is not None:
            df_scored = if_result[0]

    # FIX-3: Propagate ground_truth ke df_scored (STEP 9→10)
    if (df_scored is not None and df_meta_rbta is not None 
        and "ground_truth" in df_meta_rbta.columns 
        and "meta_id" in df_meta_rbta.columns):
        gt_map = df_meta_rbta.set_index("meta_id")["ground_truth"]
        df_scored["ground_truth"] = (
            df_scored["meta_id"]
            .map(gt_map)
            .fillna(0)
            .astype(int)
        )
        n_gt = int(df_scored["ground_truth"].sum())
        log.info(
            "[FIX-3] Ground truth propagated → df_scored: %d positif dari %d total",
            n_gt, len(df_scored),
        )

    # STEP 10: FPR vs Reduction Rate (Landauer Figure 12)
    if df_scored is not None:
        df_tradeoff = safe_step(
            "STEP 10 — FPR vs REDUCTION RATE [Landauer Figure 12]",
            compute_fpr_vs_reduction, df_scored,
        )
        if df_tradeoff is not None and not df_tradeoff.empty:
            df_tradeoff.to_csv(f"{QUALITY_DIR}/fpr_vs_reduction.csv", index=False)
            safe_step("  PLOT: FPR vs Reduction",
                      plot_fpr_vs_reduction, df_tradeoff, FIGURES_DIR)

    # STEP 11: Noise Robustness Test (Landauer Section 6.9)
    if RUN_ROBUSTNESS_TEST:
        robust_result = safe_step(
            "STEP 11 — NOISE ROBUSTNESS TEST [Landauer Section 6.9]",
            noise_robustness_test,
            df_raw_original,
            delta_t_minutes  = optimal_dt,
            buffer_size      = BUFFER_SIZE,
            max_lateness_sec = MAX_LATENESS_SEC,
            noise_rates      = NOISE_RATES,
        )
        if robust_result is not None:
            print_robustness_table(robust_result)
            robust_result.to_csv(f"{QUALITY_DIR}/robustness_results.csv", index=False)
            safe_step("  PLOT: Robustness",
                      plot_robustness, robust_result, FIGURES_DIR)
    else:
        log.info("STEP 11 — SKIP (RUN_ROBUSTNESS_TEST=False)")

    # STEP 12: Runtime Complexity Proof (Landauer Section 6.10)
    if RUN_RUNTIME_PROOF:
        runtime_result = safe_step(
            "STEP 12 — RUNTIME COMPLEXITY PROOF O(n log k) [Landauer Section 6.10]",
            runtime_complexity_proof,
            df_raw_original,
            delta_t_minutes = optimal_dt,
            buffer_size     = BUFFER_SIZE,
        )
        if runtime_result is not None:
            runtime_result.to_csv(f"{QUALITY_DIR}/runtime_proof.csv", index=False)
            safe_step("  PLOT: Runtime Proof",
                      plot_runtime_proof, runtime_result, BUFFER_SIZE, FIGURES_DIR)
    else:
        log.info("STEP 12 — SKIP (RUN_RUNTIME_PROOF=False)")

    # STEP 13: Scenario-Based Evaluation (Two Separate Evaluation Frameworks)
    # Scenario A: RBTA evaluation (metrik utama untuk sidang)
    if df_meta_rbta is not None and not df_meta_rbta.empty:
        safe_step(
            "STEP 13A — SCENARIO A: RBTA EVALUATION (Metrik Utama)",
            scenario_a_rbta_evaluation,
            df_meta_rbta, df_meta_fixed, df_per_group, QUALITY_DIR,
        )
    else:
        log.warning("STEP 13A — SKIP (df_meta_rbta tidak tersedia)")

    # Scenario B: IF evaluation (komponen pendukung, proof of concept)
    scored_csv = f"{FINAL_DIR}/meta_alerts_scored.csv"
    if df_scored is None and os.path.exists(scored_csv):
        df_scored = pd.read_csv(scored_csv)

    if df_scored is not None:
        safe_step(
            "STEP 13B — SCENARIO B: IF EVALUATION (Proof of Concept)",
            scenario_b_if_evaluation,
            df_scored, QUALITY_DIR,
        )

        has_gt = ("ground_truth" in df_scored.columns
                  and df_scored["ground_truth"].sum() > 0)
        if has_gt:
            pr_auc = compute_pr_auc(df_scored)
            safe_step("  PLOT: PR Curve",
                      plot_pr_curve, df_scored, pr_auc, FIGURES_DIR)
    else:
        log.warning("STEP 13B — SKIP (df_scored tidak tersedia)")

    # STEP 14: Detail plots per Δt (reuse cache)
    log.info("STEP 14 — DETAIL PLOTS (cache sensitivity)")
    for dt in DELTA_T_VALUES:
        df_dt       = meta_map.get(dt)
        elastic_obj = elastic_map.get(dt)
        wmark_obj   = wmark_map.get(dt)

        if df_dt is not None and not df_dt.empty:
            try:
                plot_severity_dist(df_dt, dt, output_dir=FIGURES_DIR)
                plot_alert_count_dist(df_dt, dt, output_dir=FIGURES_DIR)
            except Exception as e:
                log.warning("Plot Δt=%d gagal: %s", dt, e)

        if dt == optimal_dt and elastic_obj and wmark_obj:
            try:
                plot_elastic_dt_history(elastic_obj, dt, output_dir=FIGURES_DIR)
                plot_watermark_stats(wmark_obj, output_dir=FIGURES_DIR)
                print_enhancement_report(wmark_obj, elastic_obj, BUFFER_SIZE)
            except Exception as e:
                log.warning("Enhancement plot gagal: %s", e)

    # Summary
    elapsed = (time.perf_counter() - t_global) / 60
    log.info("#" * 70)
    log.info("  PIPELINE SELESAI")
    log.info("  Total time    : %.2f menit", elapsed)
    log.info("  Δt optimal    : %d menit", optimal_dt)
    log.info("  Injeksi aktif : %s", USE_INJECTED_DATA)
    log.info("  Robustness    : %s", RUN_ROBUSTNESS_TEST)
    log.info("  Runtime proof : %s", RUN_RUNTIME_PROOF)
    log.info("  Output dir    : %s/ dan %s/", AGG_DIR, FINAL_DIR)
    log.info("  Grafik        : %s/", FIGURES_DIR)
    log.info("  Report        : %s/", QUALITY_DIR)
    log.info("#" * 70)

    del df_raw_original, df_raw_injected
    gc.collect()


if __name__ == "__main__":
    main()