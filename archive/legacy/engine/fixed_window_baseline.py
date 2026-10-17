"""
fixed_window_baseline.py  —  Baseline Skenario A (skema paritas RBTA v4)
=========================================================================
Perubahan dari versi sebelumnya:

  [ADAPT-1] Tidak ada perubahan pada logika inti Fixed Window.

  [ADAPT-2] 4 kolom baru ditambahkan ke FixedMetaAlert agar skema
      output identik dengan RBTA v4 (9 fitur Isolation Forest):
        - unique_rules_triggered  : jumlah rule_id unik dalam bucket
        - external_threat_count   : alert dari IP eksternal
        - internal_src_count      : alert dari IP internal
        - mitre_hit_count         : alert yang memiliki has_mitre == 1

  [ADAPT-3] to_dict() menghasilkan kolom yang identik dengan MetaAlert.to_dict()
      di rbta_algorithm_02.py agar perbandingan apples-to-apples di
      evaluation_03.py dan isolation_forest.py berjalan benar.

Skenario A (Fixed Tumbling Window) vs Skenario B (RBTA Enhanced):
  A  Fixed Tumbling Window  ->  meta-alert  ->  Isolation Forest
  B  RBTA Enhanced          ->  meta-alert  ->  Isolation Forest
"""

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Optional

import numpy as np
import pandas as pd

from src.engine.rbta_core import (
    AGENT_CRITICALITY,
    DEFAULT_CRITICALITY,
    RULE_GROUP_SEVERITY_ENC,
    DEFAULT_GROUP_ENC,
)

log = logging.getLogger(__name__)


# Struktur Meta-Alert (skema identik dengan RBTA v4)

@dataclass
class FixedMetaAlert:
    meta_id:           int
    agent_id:          str
    agent_name:        str
    rule_groups:       str
    window_start:      pd.Timestamp
    window_end:        pd.Timestamp
    start_time:        pd.Timestamp
    end_time:          pd.Timestamp
    alert_count:       int        = 1
    max_severity:      int        = 0
    criticality_score: int        = 1

    # [ADAPT-2] Field baru untuk paritas skema dengan RBTA v4
    external_threat_count: int        = 0
    internal_src_count:    int        = 0
    mitre_hit_count:       int        = 0

    srcip_list:    list[str] = field(default_factory=list)
    rule_id_dist:  dict      = field(default_factory=dict)
    severity_dist: dict      = field(default_factory=dict)
    late_dropped:  int       = 0
    _unique_rule_ids: set = field(default_factory=set, repr=False)

    def to_dict(self) -> dict:
        # FIX-1: Guard semua timestamp sebelum dipakai (NaTType does not support strftime)
        def safe_strftime(ts, fallback="1970-01-01T00:00:00Z"):
            """Format timestamp dengan fallback untuk NaT/None."""
            try:
                if pd.isna(ts):
                    return fallback
                return ts.strftime("%Y-%m-%dT%H:%M:%SZ")
            except (ValueError, AttributeError, TypeError):
                return fallback

        # Guard duration_sec
        try:
            if pd.isna(self.start_time) or pd.isna(self.end_time):
                duration_sec = 0
            else:
                duration_sec = max(0, int((self.end_time - self.start_time).total_seconds()))
        except (TypeError, ValueError):
            duration_sec = 0

        clean_rg     = self.rule_groups.strip().lower()

        agent_crit = self.criticality_score
        if agent_crit == 1:
            agent_crit = AGENT_CRITICALITY.get(
                self.agent_name.strip().lower(), DEFAULT_CRITICALITY
            )

        hour_of_day             = self.start_time.hour if not pd.isna(self.start_time) else 0
        rule_group_severity_enc = RULE_GROUP_SEVERITY_ENC.get(clean_rg, DEFAULT_GROUP_ENC)
        unique_rules_triggered  = len(self._unique_rule_ids)

        return {
            "meta_id":                  self.meta_id,
            "agent_id":                 self.agent_id,
            "agent_name":               self.agent_name,
            "rule_groups":              clean_rg,
            "window_start":             safe_strftime(self.window_start),
            "window_end":               safe_strftime(self.window_end),
            "start_time":               safe_strftime(self.start_time),
            "end_time":                 safe_strftime(self.end_time),
            "duration_sec":             duration_sec,
            # Fitur f1-f9 (identik dengan RBTA v4)
            "alert_count":              self.alert_count,               # f1
            "max_severity":             self.max_severity,              # f2
            # f3: duration_sec
            "attacker_count":           len(set(ip for ip in self.srcip_list if ip)),  # f4
            "rule_group_severity_enc":  rule_group_severity_enc,        # f5
            "agent_criticality":        agent_crit,                     # f6
            "hour_of_day":              hour_of_day,                    # f7
            "unique_rules_triggered":   unique_rules_triggered,         # f8 [BARU]
            "mitre_hit_count":          self.mitre_hit_count,           # f9 [BARU]
            # Kolom konteks
            "external_threat_count":    self.external_threat_count,
            "internal_src_count":       self.internal_src_count,
            "attacker_ips":             "|".join(sorted(set(ip for ip in self.srcip_list if ip))),
            "rule_id_dist":             json.dumps(self.rule_id_dist),
            "severity_dist":            json.dumps(self.severity_dist),
            "late_dropped":             self.late_dropped,
        }


# Fixed Tumbling Window Aggregation

def run_fixed_window(
    df:              pd.DataFrame,
    delta_t_minutes: int = 15,
) -> tuple[pd.DataFrame, dict[int, list[int]]]:
    """
    Agregasi Fixed Tumbling Window — Baseline Skenario A.

    Perbedaan kritis dengan RBTA:
      - Tidak ada Elastic Delta-t
      - Tidak ada Out-of-Order Buffer
      - Tidak ada Watermark / grace period
      - Window dipotong kalender, bukan jeda antar-alert

    Parameters
    ----------
    df              : DataFrame output preprocessing_01 (arrival order).
    delta_t_minutes : Ukuran window statis dalam menit.

    Returns
    -------
    df_meta         : DataFrame meta-alert (skema identik dengan RBTA v4).
    alert_index_map : dict { meta_id: [row_indices] }
    """
    delta_t_sec = delta_t_minutes * 60
    t_start     = time.perf_counter()

    df = df.copy()

    if not pd.api.types.is_datetime64_any_dtype(df["timestamp"]):
        _t = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
        try:
            df["timestamp"] = _t.dt.tz_convert(None)
        except Exception:
            df["timestamp"] = _t.apply(
                lambda x: x.replace(tzinfo=None) if not pd.isna(x) else pd.NaT
            )
        df = df.dropna(subset=["timestamp"]).reset_index(drop=True)

    if pd.api.types.is_datetime64tz_dtype(df["timestamp"]):
        df["timestamp"] = df["timestamp"].dt.tz_convert(None)

    df["_unix"] = df["timestamp"].astype(np.int64) // 10**9
    df["_win"]  = df["_unix"] // delta_t_sec

    meta_alerts:     list[FixedMetaAlert] = []
    alert_index_map: dict[int, list[int]] = {}
    meta_id_ctr = 1

    for win_id, win_group in df.groupby("_win"):
        win_start_ts = pd.Timestamp(win_id * delta_t_sec, unit="s")
        win_end_ts   = win_start_ts + timedelta(seconds=delta_t_sec)

        for (agent_id, rule_groups), bucket in win_group.groupby(
            ["agent_id", "rule_groups"]
        ):
            alert_count = len(bucket)
            max_sev     = int(bucket["rule_level"].max())
            ips         = bucket["srcip"].replace("", np.nan).dropna().tolist()

            crit_score = int(bucket["criticality_score"].iloc[0]) \
                if "criticality_score" in bucket.columns else DEFAULT_CRITICALITY

            # [ADAPT-2] Hitung field baru
            srcip_types = bucket.get("srcip_type", pd.Series(["none"] * len(bucket)))
            ext_count   = (srcip_types == "external").sum()
            int_count   = (srcip_types == "internal").sum()
            mitre_sum   = int(bucket.get("has_mitre", pd.Series([0] * len(bucket))).sum())

            rule_id_dist: dict = {}
            sev_dist:     dict = {}
            unique_rids:  set  = set()

            for _, row in bucket.iterrows():
                rid = str(int(row.get("rule_id", 0)))
                lv  = str(int(row.get("rule_level", 0)))
                rule_id_dist[rid] = rule_id_dist.get(rid, 0) + 1
                sev_dist[lv]      = sev_dist.get(lv, 0) + 1
                unique_rids.add(rid)

            ma = FixedMetaAlert(
                meta_id               = meta_id_ctr,
                agent_id              = str(agent_id),
                agent_name            = str(bucket["agent_name"].iloc[0])
                                        if "agent_name" in bucket.columns else str(agent_id),
                rule_groups           = str(rule_groups),
                window_start          = win_start_ts,
                window_end            = win_end_ts,
                start_time            = bucket["timestamp"].min(),
                end_time              = bucket["timestamp"].max(),
                alert_count           = alert_count,
                max_severity          = max_sev,
                criticality_score     = crit_score,
                external_threat_count = int(ext_count),
                internal_src_count    = int(int_count),
                mitre_hit_count       = mitre_sum,
                srcip_list            = ips,
                rule_id_dist          = rule_id_dist,
                severity_dist         = sev_dist,
            )
            ma._unique_rule_ids = unique_rids

            meta_alerts.append(ma)
            alert_index_map[meta_id_ctr] = bucket.index.tolist()
            meta_id_ctr += 1

    elapsed_ms = (time.perf_counter() - t_start) * 1000

    if not meta_alerts:
        log.warning("Fixed Window tidak menghasilkan meta-alert.")
        return pd.DataFrame(), {}

    df_meta = (
        pd.DataFrame([m.to_dict() for m in meta_alerts])
        .sort_values("start_time")
        .reset_index(drop=True)
    )

    n_raw  = len(df)
    n_meta = len(df_meta)
    arr    = (1 - n_meta / n_raw) * 100

    log.info(
        "Fixed Window selesai — Delta-t=%d menit  raw=%d  meta=%d  ARR=%.2f%%  t=%.2fms",
        delta_t_minutes, n_raw, n_meta, arr, elapsed_ms,
    )

    return df_meta, alert_index_map


# Tabel Komparasi Loss Data

def loss_analysis(
    df_raw:          pd.DataFrame,
    df_fixed:        pd.DataFrame,
    df_rbta:         pd.DataFrame,
    delta_t_minutes: int = 15,
) -> pd.DataFrame:
    """
    Hitung Tabel Komparasi Loss Data antara Fixed Window dan RBTA.

    Fokus pada serangan yang terpotong oleh Fixed Window vs yang
    dipertahankan utuh oleh RBTA dalam satu bucket.

    Returns
    -------
    pd.DataFrame ringkasan komparasi per rule_groups.
    """
    log.info("Komparasi Loss Data — Delta-t = %d menit", delta_t_minutes)

    rows: list[dict] = []

    for group in df_raw["rule_groups"].unique():
        raw_sub   = df_raw[df_raw["rule_groups"] == group]
        fixed_sub = df_fixed[df_fixed["rule_groups"] == group] \
                    if "rule_groups" in df_fixed.columns else pd.DataFrame()
        rbta_sub  = df_rbta[df_rbta["rule_groups"] == group] \
                    if "rule_groups" in df_rbta.columns else pd.DataFrame()

        n_raw_alerts     = len(raw_sub)
        n_fixed          = len(fixed_sub)
        n_rbta           = len(rbta_sub)
        avg_alerts_fixed = fixed_sub["alert_count"].mean() if len(fixed_sub) > 0 else 0.0
        avg_alerts_rbta  = rbta_sub["alert_count"].mean()  if len(rbta_sub)  > 0 else 0.0
        median_count     = fixed_sub["alert_count"].median() if len(fixed_sub) > 0 else 0
        n_fragmented     = int((fixed_sub["alert_count"] < median_count / 2).sum()) \
                           if len(fixed_sub) > 0 else 0
        arr_fixed        = (1 - n_fixed / n_raw_alerts) * 100 if n_raw_alerts > 0 else 0.0
        arr_rbta         = (1 - n_rbta  / n_raw_alerts) * 100 if n_raw_alerts > 0 else 0.0

        rows.append({
            "Rule Group":         group,
            "Raw Alerts":         n_raw_alerts,
            "Fixed n_meta":       n_fixed,
            "RBTA n_meta":        n_rbta,
            "ARR Fixed (%)":      round(arr_fixed, 1),
            "ARR RBTA (%)":       round(arr_rbta, 1),
            "D ARR (RBTA-Fixed)": round(arr_rbta - arr_fixed, 1),
            "Avg Alerts/Fixed":   round(avg_alerts_fixed, 1),
            "Avg Alerts/RBTA":    round(avg_alerts_rbta, 1),
            "Fixed Fragmented":   n_fragmented,
        })

    df_loss = pd.DataFrame(rows).sort_values("Raw Alerts", ascending=False)
    log.info("\n%s", df_loss.to_string(index=False))
    return df_loss


# Entry Point

if __name__ == "__main__":
    import sys
    sys.path.insert(0, ".")
    from etl.preprocessing_01 import load_and_prepare

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    csv_path = sys.argv[1] if len(sys.argv) > 1 else "data/rbta_ready_all.csv"
    df_raw   = load_and_prepare(csv_path)

    df_fixed, idx_map_fixed = run_fixed_window(df_raw, delta_t_minutes=15)
    log.info("Sample 5 baris df_fixed:\n%s", df_fixed[[
        "meta_id", "agent_id", "rule_groups", "alert_count",
        "max_severity", "duration_sec", "unique_rules_triggered",
        "mitre_hit_count", "external_threat_count",
    ]].head(5).to_string())