"""
feature_engineering.py  —  HIDS-Optimized Feature Engineering v2
=================================================================
Redesain dari v1 berdasarkan analisis data aktual meta_alerts_rbta.csv.

LATAR BELAKANG REDESAIN (wajib dicantumkan di Bab 3):
  Evaluasi distribusi fitur v1 menunjukkan masalah sistemik:

    rule_group_entropy      : 92.9% = 0.0  (IQR = 0)
    tactic_progression_score: 91.3% = 0.0  (IQR = 0)
    mitre_hit_count         : 79.2% = 0    (IQR = 0)
    unique_rules_triggered  : 92.9% = 1    (IQR = 0)
    rule_firedtimes         : TIDAK ADA di output RBTA → konstan 1

  Root cause: 49.0% meta-alert adalah singleton (alert_count=1, duration=0).
  Setiap fitur berbasis statistik dalam-bucket (entropy, progression, variance)
  menghasilkan nilai konstan 0 atau 1 untuk singleton — zero variance.

  Selain itu, fitur berbasis IP (cross_agent_spread, attacker_count)
  tidak relevan untuk HIDS karena alertnya bersumber dari agent lokal,
  bukan dari traffic jaringan.

PERUBAHAN DARI v1:
  [REMOVED]  f9  rule_firedtimes       → tidak ada di output MetaAlert RBTA
  [REMOVED]  f10 rule_group_entropy    → 92.9% zero, IQR=0, tidak informatif
  [REMOVED]  f11 tactic_progression   → 91.3% zero, IQR=0, MITRE coverage rendah
  [REMOVED]  f13 cross_agent_spread   → selalu 0 di HIDS, IP-based tidak relevan

  [REPLACED] f1  alert_count (raw)    → alert_count_log (log1p transform)
                 Justifikasi: alert_count outlier hingga 134,898. Log transform
                 memberikan distribusi lebih stabil untuk Isolation Forest.
                 IQR meningkat dari efektif terdistorsi → 0.916.

  [NEW]      f7  alert_velocity = alert_count / max(duration_sec, 1)
                 Intensitas burst dalam detik. Brute-force: velocity sangat tinggi.
                 Scatter noise: velocity rendah. Escapes singleton trap (IQR=0.476).
                 WAJIB didokumentasikan sebagai pengganti rule_firedtimes di Bab 3.

  [REPLACED] f9  rule_group_entropy   → rule_concentration
                 Semantik berbeda: concentration mengukur REPETITIVITAS (dominasi
                 satu rule_id). Brute-force = concentration mendekati 1.0.
                 CATATAN JUJUR: IQR tetap 0 karena singleton, namun outliernya
                 lebih bermakna untuk HIDS dibanding entropy.

  [REPLACED] f10 tactic_progression  → severity_spread
                 = max_severity - mean_severity dalam bucket.
                 Mengukur eskalasi severity dalam window: 0 = flat (uniform),
                 tinggi = severity meningkat menuju akhir window (eskalasi).
                 CATATAN JUJUR: 95.1% = 0, sparse. Namun 2.3% yang >2 adalah
                 sinyal eskalasi nyata yang penting untuk HIDS.

  [IMPROVED] f12 deviation_from_baseline: clip diperlebar dari [-3,3] ke [-5,5]
                 Eliminasi ceiling effect: sebelumnya 5.5% data menumpuk di 3.0.
                 Dengan [-5,5]: 0% data di ceiling. Outlier ekstrem terjaga.

FEATURE VECTOR FINAL — 11 FITUR (HIDS-optimized):
  f1  alert_count_log        log1p(alert_count)
  f2  max_severity           rule.level tertinggi dalam bucket
  f3  duration_sec           durasi window (67.6% singleton = 0, didokumentasikan)
  f4  rule_group_severity_enc ordinal encoding semantic rule_group
  f5  agent_criticality      bobot kritis aset target (1=Low, 4=Critical)
  f6  hour_of_day            jam kejadian (proxy anomali temporal)
  f7  alert_velocity         intensitas burst = alert_count / max(duration_sec, 1)
  f8  mitre_hit_count        sinyal MITRE ATT&CK (sparse, dipertahankan karena
                             outlier berkorelasi kuat dengan serangan nyata)
  f9  rule_concentration     dominasi satu rule_id = repetitivitas serangan
  f10 severity_spread        eskalasi severity dalam bucket
  f11 deviation_from_baseline deviasi dari baseline 24 jam per-agent (clip [-5,5])

REMOVED (tidak digunakan):
  - cross_agent_spread  : selalu 0 di HIDS
  - rule_firedtimes     : tidak ada di output RBTA
  - rule_group_entropy  : 92.9% zero
  - tactic_progression  : 91.3% zero

Cara penggunaan:
    from src.engine.feature_engineering import enrich_features
    df_meta = enrich_features(df_meta)
"""

import json
import logging
import numpy as np
import pandas as pd
from typing import Optional

log = logging.getLogger(__name__)

# Konstanta window
BASELINE_WINDOW_HOURS = 24
DEVIATION_CLIP        = (-5.0, 5.0)   # Diperlebar dari [-3,3] untuk eliminasi ceiling effect

# Feature cols sinkron dengan isolation_forest.py
# WAJIB: update isolation_forest.py FEATURE_COLS setelah perubahan ini
FEATURE_COLS_V2 = [
    "alert_count_log",          # f1
    "max_severity",             # f2
    "duration_sec",             # f3
    "rule_group_severity_enc",  # f4
    "agent_criticality",        # f5
    "hour_of_day",              # f6
    "alert_velocity",           # f7  NEW
    "mitre_hit_count",          # f8
    "rule_concentration",       # f9  NEW
    "severity_spread",          # f10 NEW
    "deviation_from_baseline",  # f11 (clip diperlebar)
]


# f1 — alert_count_log  (log1p transform)

def add_alert_count_log(df_meta: pd.DataFrame) -> pd.DataFrame:
    """
    Tambahkan kolom alert_count_log (f1) — log1p(alert_count).

    Justifikasi:
      alert_count di data INSTIKI memiliki outlier ekstrem (max=134,898).
      Raw alert_count mendistorsi RobustScaler dan IF karena satu bucket
      mendominasi feature space. log1p mengkompresi distribusi menjadi
      [0, ~11.8] dengan IQR=0.916 vs IQR=3 pada raw count.

      Catatan: alert_count RAW tetap dipertahankan di CSV untuk audit.
      alert_count_log adalah yang masuk ke feature matrix IF.

    Kompleksitas: O(n)
    """
    df = df_meta.copy()

    if "alert_count" not in df.columns:
        log.warning("Kolom alert_count tidak ditemukan — alert_count_log di-set 0.")
        df["alert_count_log"] = 0.0
        return df

    alert_count = pd.to_numeric(df["alert_count"], errors="coerce").fillna(1).clip(lower=1)
    df["alert_count_log"] = np.log1p(alert_count).round(4)

    log.info(
        "f1 alert_count_log: min=%.3f  median=%.3f  max=%.3f  IQR=%.3f",
        df["alert_count_log"].min(),
        df["alert_count_log"].median(),
        df["alert_count_log"].max(),
        df["alert_count_log"].quantile(0.75) - df["alert_count_log"].quantile(0.25),
    )
    return df


# f7 — alert_velocity  (NEW — menggantikan rule_firedtimes yang tidak ada)

def add_alert_velocity(df_meta: pd.DataFrame) -> pd.DataFrame:
    """
    Tambahkan kolom alert_velocity (f7) = alert_count / max(duration_sec, 1).

    Justifikasi:
      Mengukur intensitas burst dalam detik. Ini adalah proxy yang valid
      untuk rule_firedtimes (yang tidak dihasilkan MetaAlert RBTA) karena:
        - Brute-force SSH: 100 alerts / 10 detik = velocity=10
        - Scan port: 50 alerts / 300 detik = velocity=0.17
        - Normal log rotation: 1 alert / 0 detik = velocity=1

      Fitur ini escapes singleton trap: velocity bisa tinggi bahkan untuk
      duration=0 jika alert_count besar dalam satu timestamp.

    Handling duration_sec = 0:
      max(duration_sec, 1) sehingga singleton (duration=0, count=1) → velocity=1.
      Nilai velocity=1 adalah baseline HIDS normal, bukan anomali.

    Kompleksitas: O(n)
    """
    df = df_meta.copy()

    if "alert_count" not in df.columns or "duration_sec" not in df.columns:
        log.warning("Kolom alert_count atau duration_sec tidak ditemukan — alert_velocity di-set 1.")
        df["alert_velocity"] = 1.0
        return df

    alert_count  = pd.to_numeric(df["alert_count"], errors="coerce").fillna(1).clip(lower=0)
    duration_sec = pd.to_numeric(df["duration_sec"], errors="coerce").fillna(0).clip(lower=0)

    # Clip duration minimum ke 1 untuk menghindari division by zero
    df["alert_velocity"] = (alert_count / duration_sec.clip(lower=1)).round(4)

    iqr = df["alert_velocity"].quantile(0.75) - df["alert_velocity"].quantile(0.25)
    log.info(
        "f7 alert_velocity: min=%.3f  median=%.3f  max=%.2f  IQR=%.3f  nunique=%d",
        df["alert_velocity"].min(),
        df["alert_velocity"].median(),
        df["alert_velocity"].max(),
        iqr,
        df["alert_velocity"].nunique(),
    )
    return df


# f9 — rule_concentration  (menggantikan rule_group_entropy)

def _parse_json_dist(val: object) -> dict:
    """Helper: parse JSON string distribusi → dict. Return {} jika gagal."""
    if pd.isna(val) or val == "" or val is None:
        return {}
    try:
        if isinstance(val, dict):
            return val
        return json.loads(str(val))
    except (json.JSONDecodeError, TypeError, ValueError):
        return {}


def _compute_concentration(dist_dict: dict) -> float:
    """
    Hitung rule concentration = max_count / total_count.

    Nilai 1.0: semua alert berasal dari satu rule_id (brute-force / scan).
    Nilai rendah: rule_id terdiversifikasi (multi-stage atau noise).

    CATATAN AKADEMIS (Bab 3):
      95% meta-alert singleton menghasilkan concentration=1.0, sama dengan
      rule_group_entropy=0. Perbedaan semantik: concentration lebih intuitif
      untuk HIDS — repetisi satu rule adalah sinyal monotone attack.
      Fitur ini paling informatif pada meta-alert non-singleton (alert_count>1).
    """
    if not dist_dict:
        return 1.0
    total = sum(dist_dict.values())
    if total <= 0:
        return 1.0
    return round(max(dist_dict.values()) / total, 4)


def add_rule_concentration(df_meta: pd.DataFrame) -> pd.DataFrame:
    """
    Tambahkan kolom rule_concentration (f9) ke df_meta.

    Menggunakan kolom rule_id_dist (output rbta_algorithm_02.py).
    Fallback ke nilai 1.0 jika kolom tidak ada.

    Kompleksitas: O(n * k) dimana k = jumlah rule_id unik per bucket.
    """
    df = df_meta.copy()

    if "rule_id_dist" not in df.columns:
        log.warning("Kolom rule_id_dist tidak ditemukan — rule_concentration di-set 1.0.")
        df["rule_concentration"] = 1.0
        return df

    df["rule_concentration"] = df["rule_id_dist"].apply(
        lambda v: _compute_concentration(_parse_json_dist(v))
    )

    n_diverse = (df["rule_concentration"] < 0.8).sum()
    log.info(
        "f9 rule_concentration: median=%.3f  nunique=%d  "
        "diverse (< 0.8): %d baris (%.1f%%)",
        df["rule_concentration"].median(),
        df["rule_concentration"].nunique(),
        n_diverse,
        n_diverse / len(df) * 100,
    )
    return df


# f10 — severity_spread  (menggantikan tactic_progression_score)

def _compute_severity_mean(severity_dist: dict) -> float:
    """Hitung rata-rata severity dari distribusi {level: count}."""
    if not severity_dist:
        return 0.0
    total = sum(severity_dist.values())
    if total <= 0:
        return 0.0
    weighted = sum(int(k) * v for k, v in severity_dist.items())
    return weighted / total


def add_severity_spread(df_meta: pd.DataFrame) -> pd.DataFrame:
    """
    Tambahkan kolom severity_spread (f10) = max_severity - severity_mean.

    Justifikasi:
      Menggantikan tactic_progression yang bergantung pada MITRE coverage
      rendah (13.7% di dataset INSTIKI). severity_spread menggunakan
      severity_dist yang tersedia di semua meta-alert.

      Interpretasi:
        severity_spread = 0   : severity flat (uniform, expected untuk known ops)
        severity_spread > 0   : severity naik dalam window (eskalasi bertahap)
        severity_spread tinggi: alert awal ringan, diakhiri severity tinggi
                                (pola APT: recon → exploit → exfil)

    CATATAN AKADEMIS (Bab 3):
      95.1% = 0 karena 67.6% singleton. Untuk singleton: max = mean → spread = 0.
      Fitur bermakna hanya untuk non-singleton. Dipertahankan karena 2.3% dengan
      spread > 2 merupakan sinyal eskalasi nyata yang tidak tertangkap fitur lain.

    Kompleksitas: O(n * k) dimana k = jumlah level severity unik per bucket.
    """
    df = df_meta.copy()

    if "severity_dist" not in df.columns or "max_severity" not in df.columns:
        log.warning("Kolom severity_dist atau max_severity tidak ditemukan — severity_spread di-set 0.")
        df["severity_spread"] = 0.0
        return df

    max_sev = pd.to_numeric(df["max_severity"], errors="coerce").fillna(0)

    sev_mean = df["severity_dist"].apply(
        lambda v: _compute_severity_mean(_parse_json_dist(v))
    )

    # clip lower=0: spread tidak boleh negatif (floating point rounding edge case)
    df["severity_spread"] = (max_sev - sev_mean).clip(lower=0).round(4)

    n_escalate = (df["severity_spread"] > 2).sum()
    log.info(
        "f10 severity_spread: median=%.3f  max=%.2f  "
        "eskalasi (>2): %d baris (%.1f%%)",
        df["severity_spread"].median(),
        df["severity_spread"].max(),
        n_escalate,
        n_escalate / len(df) * 100,
    )
    return df


# f11 — deviation_from_baseline  (clip diperlebar ke [-5, 5])

def compute_deviation_from_baseline(
    df_meta:      pd.DataFrame,
    window_hours: int = BASELINE_WINDOW_HOURS,
) -> pd.DataFrame:
    """
    Hitung deviation_from_baseline (f11) = (current - baseline_mean) / baseline_mean.

    PERUBAHAN dari v1:
      Clip diperlebar dari [-3, 3] → [-5, 5].
      Justifikasi: clip [-3,3] menyebabkan 5.5% data (3,489 baris) menumpuk
      di ceiling 3.0. Dengan [-5,5]: 0% data di ceiling, outlier ekstrem
      (burst 134,898 alerts) tetap terjaga sebagai sinyal anomali.

    Interpretasi:
      Positif: lebih tinggi dari biasanya → kandidat anomali burst
      Negatif: lebih rendah dari biasanya → mungkin evasion atau low-and-slow
      0:       tidak ada data historis atau sesuai rata-rata

    Kompleksitas: O(n²) — cukup untuk batch CSV < 100k baris.

    Parameters
    ----------
    df_meta      : DataFrame dengan kolom start_time, agent_name, alert_count.
    window_hours : lebar window baseline dalam jam (default 24 jam).

    Returns
    -------
    pd.DataFrame dengan kolom deviation_from_baseline (float, clipped ke DEVIATION_CLIP).
    """
    import time
    t0 = time.perf_counter()

    df = df_meta.copy()
    df["start_time"] = pd.to_datetime(df["start_time"], errors="coerce")

    n = len(df)
    if n == 0:
        df["deviation_from_baseline"] = 0.0
        return df

    df_sorted  = df.sort_values("start_time").reset_index(drop=True)
    deviations = np.zeros(n, dtype=float)
    window_td  = pd.Timedelta(hours=window_hours)

    for i in range(n):
        t_now  = df_sorted.at[i, "start_time"]
        agent  = df_sorted.at[i, "agent_name"]
        t_from = t_now - window_td

        mask_baseline = (
            (df_sorted["agent_name"] == agent) &
            (df_sorted["start_time"] >= t_from) &
            (df_sorted["start_time"] < t_now)
        )
        baseline_rows = df_sorted.loc[mask_baseline, "alert_count"]

        if len(baseline_rows) == 0:
            deviations[i] = 0.0
        else:
            baseline_mean = baseline_rows.mean()
            if baseline_mean > 0:
                deviations[i] = (
                    df_sorted.at[i, "alert_count"] - baseline_mean
                ) / baseline_mean
            else:
                deviations[i] = 0.0

    # Clip ke DEVIATION_CLIP = [-5, 5] (diperlebar dari [-3, 3])
    df_sorted["deviation_from_baseline"] = np.clip(
        deviations, DEVIATION_CLIP[0], DEVIATION_CLIP[1]
    ).round(4)

    # Kembalikan ke urutan original
    df_sorted = df_sorted.set_index(df.sort_values("start_time").index)
    df["deviation_from_baseline"] = df_sorted["deviation_from_baseline"].values

    elapsed = (time.perf_counter() - t0) * 1000
    pct_ceiling = (df["deviation_from_baseline"] == DEVIATION_CLIP[1]).mean() * 100
    log.info(
        "f11 deviation_from_baseline: min=%.3f  median=%.3f  max=%.3f  "
        "ceiling(%+.0f): %.1f%%  (%.0fms, window=%dh, clip=[%.0f,%.0f])",
        df["deviation_from_baseline"].min(),
        df["deviation_from_baseline"].median(),
        df["deviation_from_baseline"].max(),
        DEVIATION_CLIP[1], pct_ceiling,
        elapsed, window_hours,
        DEVIATION_CLIP[0], DEVIATION_CLIP[1],
    )
    return df


# Pipeline: enrich_features — terapkan semua fitur v2

def enrich_features(
    df_meta:               pd.DataFrame,
    baseline_window_hours: int = BASELINE_WINDOW_HOURS,
) -> pd.DataFrame:
    """
    Terapkan semua fitur HIDS-optimized (f1-f11) ke df_meta secara berurutan.

    FITUR YANG DIHITUNG:
      f1  add_alert_count_log          O(n)
      f7  add_alert_velocity           O(n)
      f9  add_rule_concentration       O(n * k)
      f10 add_severity_spread          O(n * k)
      f11 compute_deviation_from_baseline O(n²) — paling lambat

    FITUR YANG TIDAK LAGI DIHITUNG (v1 → v2):
      cross_agent_spread    : IP-based, selalu 0 di HIDS
      rule_group_entropy    : 92.9% zero, tidak informatif
      tactic_progression    : 91.3% zero, MITRE coverage rendah
      rule_firedtimes       : tidak ada di output RBTA

    Untuk dataset > 100k baris, pertimbangkan optimasi f11 dengan
    groupby + rolling window sebagai pengganti loop O(n²).

    Parameters
    ----------
    df_meta               : DataFrame hasil run_rbta() yang sudah melalui
                            add_if_features() dari rbta_algorithm_02.py.
    baseline_window_hours : window untuk f11 (default 24 jam).

    Returns
    -------
    pd.DataFrame dengan kolom tambahan:
      alert_count_log, alert_velocity, rule_concentration,
      severity_spread, deviation_from_baseline
    """
    import time
    t0 = time.perf_counter()

    log.info("[ENRICH v2] Memulai feature engineering HIDS-optimized ...")
    log.info("[ENRICH v2] Input: %d meta-alert, %d kolom", len(df_meta), len(df_meta.columns))

    df = add_alert_count_log(df_meta)
    log.info("[ENRICH v2] f1 selesai.")

    df = add_alert_velocity(df)
    log.info("[ENRICH v2] f7 selesai.")

    df = add_rule_concentration(df)
    log.info("[ENRICH v2] f9 selesai.")

    df = add_severity_spread(df)
    log.info("[ENRICH v2] f10 selesai.")

    df = compute_deviation_from_baseline(df, window_hours=baseline_window_hours)
    log.info("[ENRICH v2] f11 selesai.")

    elapsed = (time.perf_counter() - t0) * 1000
    log.info("[ENRICH v2] Semua fitur selesai dalam %.1f ms.", elapsed)

    # Validasi tipe numerik semua fitur
    dtype_map: dict[str, type] = {
        "alert_count_log":       float,
        "alert_velocity":        float,
        "rule_concentration":    float,
        "severity_spread":       float,
        "deviation_from_baseline": float,
    }
    for col, dtype in dtype_map.items():
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(dtype)

    _print_enrichment_summary(df)
    return df


def _print_enrichment_summary(df: pd.DataFrame) -> None:
    """Cetak ringkasan statistik semua fitur v2."""
    new_cols = [
        "alert_count_log",
        "alert_velocity",
        "rule_concentration",
        "severity_spread",
        "deviation_from_baseline",
    ]
    present = [c for c in new_cols if c in df.columns]
    if not present:
        return

    log.info("\n[ENRICH v2 SUMMARY]")
    log.info("%-35s %8s %8s %8s %8s %8s", "Fitur", "min", "median", "max", "IQR", "nunique")
    log.info("-" * 83)
    for col in present:
        s   = df[col]
        iqr = s.quantile(0.75) - s.quantile(0.25)
        log.info(
            "  %-33s %8.3f %8.3f %8.3f %8.3f %8d",
            col, s.min(), s.median(), s.max(), iqr, s.nunique(),
        )


# Standalone entry point

if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    csv_path = sys.argv[1] if len(sys.argv) > 1 else "data/aggregated/meta_alerts_rbta.csv"
    log.info("Loading: %s", csv_path)

    df = pd.read_csv(csv_path)
    df = enrich_features(df)

    out_path = csv_path.replace(".csv", "_enriched_v2.csv")
    df.to_csv(out_path, index=False)
    log.info("Saved: %s", out_path)

    # Verifikasi semua feature cols tersedia
    missing = [c for c in FEATURE_COLS_V2 if c not in df.columns]
    if missing:
        log.error("FEATURE COLS TIDAK TERSEDIA: %s", missing)
        sys.exit(1)
    log.info("Semua %d fitur tersedia. Pipeline siap.", len(FEATURE_COLS_V2))