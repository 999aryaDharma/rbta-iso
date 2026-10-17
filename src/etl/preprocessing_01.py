"""Preprocessing rbta_ready_all.csv untuk pipeline RBTA.

Kolom has_mitre dan has_critical_mitre diteruskan apa adanya dari
json_orches.py; keduanya dibutuhkan RBTA untuk mengakumulasi konteks
MITRE per bucket.
"""

import logging
import pandas as pd
import numpy as np
from pathlib import Path

log = logging.getLogger(__name__)

# Pemetaan kolom rbta_ready_all.csv → nama internal pipeline.
REQUIRED_COLS = {
    "timestamp_utc":       "timestamp",
    "agent_id":            "agent_id",
    "agent_name":          "agent_name",
    "rule_group_primary":  "rule_groups",
    "rule_level":          "rule_level",
    "srcip":               "srcip",
    "rule_id":             "rule_id",
    "criticality_score":   "criticality_score",
    # Flag MITRE dari json_orches.py.
    "has_mitre":           "has_mitre",
    "has_critical_mitre":  "has_critical_mitre",
}

OPTIONAL_COLS = {
    "srcip_type":          "srcip_type",
    "agent_criticality":   "agent_criticality_label",
    "rule_firedtimes":     "rule_firedtimes",
    "mitre_tactic":        "mitre_tactic",
    "mitre_id":            "mitre_id",
}

_HASH_TOKENS = {"md5", "sha1", "sha256", "mtime", "inode"}


def load_and_prepare(csv_path: str | Path) -> pd.DataFrame:
    """Muat rbta_ready_all.csv, buang baris rusak, dan parse tipe data.

    Kenapa tidak di-sort?
    ---------------------
    RBTA punya Out-of-Order Buffer (min-heap, O(log k)) yang memang dirancang
    untuk event yang datang tidak berurutan. Sort global di depan membuat buffer
    itu tidak pernah teruji. Kompleksitas tetap O(n).
    """
    csv_path = Path(csv_path)
    if not csv_path.exists():
        raise FileNotFoundError(f"File tidak ditemukan: {csv_path}")

    df_raw = pd.read_csv(csv_path, engine="python", on_bad_lines="skip")
    log.info(
        "[LOAD] %s → %d baris, %d kolom (sebelum filter)",
        csv_path.name, len(df_raw), df_raw.shape[1],
    )

    df_raw, n_corrupt = _drop_corrupt_rows(df_raw)

    available_req = {k: v for k, v in REQUIRED_COLS.items() if k in df_raw.columns}
    missing_req   = set(REQUIRED_COLS) - set(available_req)
    if missing_req:
        log.warning("Kolom wajib tidak ditemukan: %s", missing_req)

    # Pastikan timestamp_utc ada (cek rename).
    if "timestamp_utc" not in available_req:
        raise KeyError("Kolom 'timestamp_utc' WAJIB ada di CSV untuk RBTA pipeline")

    available_opt = {k: v for k, v in OPTIONAL_COLS.items() if k in df_raw.columns}
    all_available = {**available_req, **available_opt}

    # Pilih kolom lalu rename.
    selected_cols = [col for col in all_available.keys() if col in df_raw.columns]
    df = df_raw[selected_cols].rename(columns=all_available).copy()

    # Kolom timestamp harus ada setelah rename.
    if "timestamp" not in df.columns:
        raise KeyError(
            f"Kolom 'timestamp' tidak ditemukan setelah rename. "
            f"Available cols: {df.columns.tolist()}"
        )

    # Parse timestamp.
    _ts = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    try:
        df["timestamp"] = _ts.dt.tz_convert(None)
    except Exception:
        df["timestamp"] = _ts.apply(
            lambda x: x.replace(tzinfo=None) if not pd.isna(x) else pd.NaT
        )
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    n_bad_ts = df["timestamp"].isna().sum()
    if n_bad_ts > 0:
        log.warning("%d baris dengan timestamp tidak valid → dibuang", n_bad_ts)
        df = df.dropna(subset=["timestamp"])

    # rule_level
    if "rule_level" in df.columns:
        df["rule_level"] = (
            pd.to_numeric(df["rule_level"], errors="coerce")
            .fillna(0)
            .astype(int)
        )
        invalid_level = ~df["rule_level"].between(0, 15)
        if invalid_level.any():
            log.warning(
                "%d baris rule_level di luar range 0-15 → di-clip ke 0",
                invalid_level.sum(),
            )
            df.loc[invalid_level, "rule_level"] = 0

    # srcip
    if "srcip" in df.columns:
        df["srcip"] = df["srcip"].fillna("").astype(str).str.strip().replace("nan", "")
    else:
        df["srcip"] = ""

    # srcip_type diteruskan dari json_orches.py. Bila tidak ada (dataset lama),
    # isi "none" supaya akses kolom ini tidak error.
    if "srcip_type" not in df.columns:
        df["srcip_type"] = "none"
        log.warning(
            "Kolom srcip_type tidak ditemukan. Di-set 'none'. "
            "Pastikan dataset berasal dari json_orches.py versi terbaru."
        )
    else:
        df["srcip_type"] = df["srcip_type"].fillna("none").astype(str)

    # agent_id
    if "agent_id" in df.columns:
        df["agent_id"] = df["agent_id"].fillna("unknown").astype(str).str.strip()
    else:
        df["agent_id"] = "unknown"

    # rule_id
    if "rule_id" in df.columns:
        df["rule_id"] = pd.to_numeric(df["rule_id"], errors="coerce").fillna(0).astype(int)
    else:
        df["rule_id"] = 0

    # criticality_score
    if "criticality_score" in df.columns:
        df["criticality_score"] = (
            pd.to_numeric(df["criticality_score"], errors="coerce")
            .fillna(1)
            .clip(1, 4)
            .astype(int)
        )
    else:
        if "agent_criticality_label" in df.columns:
            _label_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
            df["criticality_score"] = (
                df["agent_criticality_label"].str.lower()
                .map(_label_map)
                .fillna(1)
                .astype(int)
            )
        else:
            df["criticality_score"] = 1

    # has_mitre dan has_critical_mitre
    for mitre_col in ("has_mitre", "has_critical_mitre"):
        if mitre_col in df.columns:
            df[mitre_col] = (
                pd.to_numeric(df[mitre_col], errors="coerce")
                .fillna(0)
                .clip(0, 1)
                .astype(int)
            )
        else:
            df[mitre_col] = 0
            log.warning(
                "Kolom %s tidak ditemukan — di-set 0. "
                "Pastikan json_orches.py versi terbaru yang menghasilkan CSV.",
                mitre_col,
            )

    # rule_groups
    if "rule_groups" in df.columns:
        df["rule_groups"] = (
            df["rule_groups"].fillna("unknown")
            .astype(str)
            .str.strip()
            .str.lower()
        )
    else:
        df["rule_groups"] = "unknown"

    df = df.reset_index(drop=True)
    log.info("[LOAD] Arrival order CSV dipertahankan — tidak ada global sort [O(n)]")

    # Validasi akhir: semua kolom penting harus ada.
    critical_cols = ["timestamp", "agent_id", "agent_name", "rule_groups", "rule_level"]
    missing_critical = [col for col in critical_cols if col not in df.columns]
    if missing_critical:
        log.error("KOLOM KRITIS HILANG SETELAH PREPROCESSING: %s", missing_critical)
        log.error("Available columns: %s", df.columns.tolist())
        raise KeyError(f"Kolom kritis hilang: {missing_critical}")

    _print_summary(df, n_corrupt)
    return df


# Helper: buang baris rusak.

def _drop_corrupt_rows(df: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    if "agent_id" not in df.columns:
        return df, 0

    raw_str = df["agent_id"].astype(str).str.strip().str.lower()
    mask_hash = raw_str.isin(_HASH_TOKENS)

    known_agents = {
        "soc-1", "pusatkarir", "dfir-iris", "siput",
        "proxy-manager", "e-kuesioner", "sads", "dvwa",
        "unknown", "nan",
    }
    is_numeric   = pd.to_numeric(df["agent_id"], errors="coerce").notna()
    is_known     = raw_str.isin(known_agents)
    mask_invalid = ~is_numeric & ~is_known

    corrupt_mask = mask_hash | mask_invalid
    n_corrupt    = int(corrupt_mask.sum())

    if n_corrupt > 0:
        log.info(
            "[CLEAN] %d corrupt rows di-drop (%.1f%%) — hash column bleed terdeteksi",
            n_corrupt, n_corrupt / len(df) * 100,
        )

    return df[~corrupt_mask].copy(), n_corrupt


# Helper: ringkasan.

def _print_summary(df: pd.DataFrame, n_corrupt: int = 0) -> None:
    log.info("=" * 60)
    log.info("  RINGKASAN DATA SETELAH PREPROCESSING")
    log.info("=" * 60)
    log.info("  Total raw alerts (valid)  : %d", len(df))
    if n_corrupt > 0:
        log.info("  Corrupt rows di-drop      : %d", n_corrupt)
    log.info(
        "  Rentang waktu             : %s → %s",
        df["timestamp"].min().strftime("%Y-%m-%d %H:%M"),
        df["timestamp"].max().strftime("%Y-%m-%d %H:%M"),
    )
    if "agent_id" in df.columns:
        log.info("  Jumlah agent unik         : %d", df["agent_id"].nunique())
    if "rule_groups" in df.columns:
        log.info("  Jumlah rule group unik    : %d", df["rule_groups"].nunique())
    if "has_mitre" in df.columns:
        n_mitre = df["has_mitre"].sum()
        log.info(
            "  Alert dengan MITRE flag   : %d (%.1f%%)",
            n_mitre, n_mitre / len(df) * 100,
        )
    if "criticality_score" in df.columns:
        dist = df["criticality_score"].value_counts().sort_index()
        log.info(
            "  Criticality score dist    : %s",
            " | ".join(f"{k}={v}" for k, v in dist.items()),
        )
    log.info("=" * 60)



if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    csv_file = sys.argv[1] if len(sys.argv) > 1 else "data/rbta_ready_all.csv"
    df = load_and_prepare(csv_file)
    print(df[[
        "timestamp", "agent_id", "agent_name", "rule_groups",
        "rule_level", "criticality_score", "has_mitre", "has_critical_mitre",
        "srcip_type",
    ]].head(5).to_string())
