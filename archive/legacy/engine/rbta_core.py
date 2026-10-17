"""
rbta_algorithm_02.py  —  Enhanced v5  (compound bucket + rule_group_dist)
==========================================================================
Perubahan dari v4:

  [NEW-1] MetaAlert.rule_group_dist: dict[str, int]
      Distribusi rule_group yang masuk ke bucket A ini.
      Digunakan feature_engineering.py untuk f10 (rule_group_entropy).

  [NEW-2] Compound bucket (Bucket B) berjalan paralel dengan Bucket A.
      Bucket A: key = (agent_id, rule_group)  — untuk ARR & IF standar.
      Bucket B: key = (agent_id, window_id)   — untuk behavioral sequencing.
      run_rbta() sekarang mengembalikan 5 nilai:
        (df_meta, df_compound, alert_index_map, elastic, wmark)

  [NEW-3] _process mengisi rule_group_dist setiap update bucket A.

  [COMPAT] evaluation_03.py tidak perlu diubah karena tetap menerima
      (df_meta, idx_map, elastic, wmark) — cukup unpack 5 nilai.
"""

import heapq
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import timedelta
from math import floor

import pandas as pd

log = logging.getLogger(__name__)


# Konstanta
from src.config.domain import (
    AGENT_CRITICALITY,
    DEFAULT_AGENT_CRITICALITY as DEFAULT_CRITICALITY,
)

RULE_GROUP_SEVERITY_ENC: dict[str, int] = {
    "ossec":                   1,
    "syslog":                  1,
    "authentication_success":  1,
    "stats":                   1,
    "accesslog":               1,
    "wazuh":                   1,
    "local":                   1,
    "dpkg":                    2,
    "config_changed":          2,
    "virus":                   2,
    "sudo":                    2,
    "pam":                     2,
    "sca":                     2,
    "sca_check":               2,
    "linux":                   2,
    "rootcheck":               3,
    "syscheck_file":           3,
    "syscheck_entry_deleted":  3,
    "syscheck_entry_added":    3,
    "system_error":            3,
    "docker-error":            3,
    "docker":                  3,
    "syscheck":                3,
    "windows":                 3,
    "virustotal":              3,
    "web":                     4,
    "apache":                  4,
    "nginx":                   4,
    "authentication_failed":   4,
    "audit":                   4,
    "auditd":                  4,
    "attack":                  5,
    "access_control":          5,
    "sql_injection":           6,
    "vulnerability-detector":  6,
    "webshell":                6,
    "judol_file":              6,
}
DEFAULT_GROUP_ENC = 2

# 11 Fitur core (sebelum behavioral enrichment) — v2 HIDS-optimized
# [v2] Optimization untuk HIDS:
#   - alert_count → alert_count_log (log1p transform)
#   - rule_firedtimes → alert_velocity (burst intensity)
#   - unique_rules_triggered → rule_concentration (repetitivitas)
#   - tactic_progression → severity_spread (eskalasi)
FEATURE_COLS_V5 = [
    "alert_count_log",          # f1  log1p(alert_count)
    "max_severity",             # f2  rule.level tertinggi
    "duration_sec",             # f3  durasi window
    "rule_group_severity_enc",  # f4  ordinal encoding
    "agent_criticality",        # f5  bobot kritis aset
    "hour_of_day",              # f6  jam kejadian
    "alert_velocity",           # f7  burst intensity
    "mitre_hit_count",          # f8  sinyal MITRE
    "rule_concentration",       # f9  repetitivitas rule
    "severity_spread",          # f10 eskalasi severity
    "deviation_from_baseline",  # f11 deviasi baseline 24h
]


# Out-of-Order Buffer

class OutOfOrderBuffer:
    def __init__(self, k: int = 50) -> None:
        if k < 1:
            raise ValueError("k harus >= 1")
        self.k        = k
        self._heap:    list = []
        self._counter: int  = 0

    def push(self, ts: pd.Timestamp, payload: object) -> None:
        heapq.heappush(self._heap, (ts, self._counter, payload))
        self._counter += 1

    @property
    def is_full(self) -> bool:
        return len(self._heap) >= self.k

    def __len__(self) -> int:
        return len(self._heap)


def _pop_with_idx(buf: OutOfOrderBuffer) -> tuple:
    ts, _, payload = heapq.heappop(buf._heap)
    return ts, payload


def _drain_with_idx(buf: OutOfOrderBuffer) -> list:
    result = []
    while buf._heap:
        result.append(_pop_with_idx(buf))
    return result


# Elastic Time-Window

class ElasticWindow:
    _WARMUP_SIZE = 100
    _HIGH_FREQ   = 3.0
    _LOW_FREQ    = 0.33
    _SHRINK_RATE = 0.80
    _EXPAND_RATE = 1.20

    def __init__(
        self,
        base_dt: timedelta,
        min_dt:  timedelta | None = None,
        max_dt:  timedelta | None = None,
        alpha:   float            = 0.10,
    ) -> None:
        self.base_dt    = base_dt
        self.min_dt     = min_dt or timedelta(seconds=base_dt.total_seconds() * 0.5)
        self.max_dt     = max_dt or timedelta(seconds=base_dt.total_seconds() * 1.5)
        self.alpha      = alpha
        self.current_dt = base_dt
        self._last_ts:  pd.Timestamp | None = None
        self._ema:      float | None        = None
        self._baseline: float | None        = None
        self._warmup:   list[float]         = []
        self.dt_history: list[tuple]        = []

    def update(self, ts: pd.Timestamp) -> timedelta:
        if self._last_ts is not None:
            gap = (ts - self._last_ts).total_seconds()
            if gap > 0:
                if self._baseline is None:
                    self._warmup.append(gap)
                    if len(self._warmup) >= self._WARMUP_SIZE:
                        self._baseline = sum(self._warmup) / len(self._warmup)
                        self._ema      = self._baseline
                else:
                    self._ema = self.alpha * gap + (1 - self.alpha) * self._ema
                    self._adapt()
        self._last_ts = ts
        self.dt_history.append((ts, self.current_dt.total_seconds() / 60))
        return self.current_dt

    @property
    def current_minutes(self) -> float:
        return self.current_dt.total_seconds() / 60

    @property
    def is_warmed_up(self) -> bool:
        return self._baseline is not None

    def _adapt(self) -> None:
        if not self._ema or self._ema <= 0:
            return
        ratio = self._baseline / self._ema
        if ratio >= self._HIGH_FREQ:
            self.current_dt = max(
                timedelta(seconds=self.current_dt.total_seconds() * self._SHRINK_RATE),
                self.min_dt,
            )
        elif ratio <= self._LOW_FREQ:
            self.current_dt = min(
                timedelta(seconds=self.current_dt.total_seconds() * self._EXPAND_RATE),
                self.max_dt,
            )


# Watermark

class Watermark:
    def __init__(self, max_lateness_sec: float = 10.0) -> None:
        if max_lateness_sec < 0:
            raise ValueError("max_lateness_sec harus >= 0")
        self.max_lateness = timedelta(seconds=max_lateness_sec)
        self._max_seen:   pd.Timestamp | None = None
        self.n_on_time:   int = 0
        self.n_late_ok:   int = 0
        self.n_late_drop: int = 0

    def advance(self, ts) -> None:
        if not isinstance(ts, pd.Timestamp):
            try:
                ts = pd.Timestamp(ts)
            except Exception:
                return
        if self._max_seen is None or ts > self._max_seen:
            self._max_seen = ts

    def classify(self, ts) -> str:
        if not isinstance(ts, pd.Timestamp):
            try:
                ts = pd.Timestamp(ts)
            except Exception:
                self.n_on_time += 1
                return "on_time"
        wm = self.watermark
        if wm is None or ts >= wm:
            self.n_on_time += 1
            return "on_time"
        if ts >= self._max_seen - 2 * self.max_lateness:
            self.n_late_ok += 1
            return "late_ok"
        self.n_late_drop += 1
        return "late_drop"

    @property
    def watermark(self) -> pd.Timestamp | None:
        if self._max_seen is None:
            return None
        return self._max_seen - self.max_lateness


# MetaAlert (Bucket A)

@dataclass
class MetaAlert:
    meta_id:           int
    agent_id:          str
    agent_name:        str
    rule_groups:       str
    start_time:        pd.Timestamp
    end_time:          pd.Timestamp
    parent_meta_id:    int | None = None
    alert_count:       int        = 1
    max_severity:      int        = 0
    criticality_score: int        = 1
    external_threat_count: int    = 0
    internal_src_count:    int    = 0
    mitre_hit_count:       int    = 0
    mitre_tactic_list:     list[str] = field(default_factory=list)
    srcip_list:       list[str]   = field(default_factory=list)
    rule_id_dist:     dict        = field(default_factory=dict)
    severity_dist:    dict        = field(default_factory=dict)
    rule_group_dist:  dict        = field(default_factory=dict)  # [NEW-1]
    wazuh_alert_ids:  list[str]   = field(default_factory=list)  # [FIX-A] Untuk traceability
    _unique_rule_ids: set         = field(default_factory=set, repr=False)

    def to_dict(self) -> dict:
        duration_sec = max(0, int((self.end_time - self.start_time).total_seconds()))
        clean_rg     = self.rule_groups.strip().lower()
        agent_crit   = self.criticality_score
        if agent_crit == 1:
            agent_crit = AGENT_CRITICALITY.get(self.agent_name.strip().lower(), DEFAULT_CRITICALITY)
        return {
            "meta_id":                  self.meta_id,
            "parent_meta_id":           self.parent_meta_id if self.parent_meta_id else "",
            "agent_id":                 self.agent_id,
            "agent_name":               self.agent_name,
            "rule_groups":              clean_rg,
            "start_time":               self.start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "end_time":                 self.end_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "duration_sec":             duration_sec,
            "alert_count":              self.alert_count,
            "max_severity":             self.max_severity,
            "attacker_count":           len(set(ip for ip in self.srcip_list if ip)),
            "rule_group_severity_enc":  RULE_GROUP_SEVERITY_ENC.get(clean_rg, DEFAULT_GROUP_ENC),
            "agent_criticality":        agent_crit,
            "hour_of_day":              self.start_time.hour,
            "unique_rules_triggered":   len(self._unique_rule_ids),
            "mitre_hit_count":          self.mitre_hit_count,
            "external_threat_count":    self.external_threat_count,
            "internal_src_count":       self.internal_src_count,
            "attacker_ips":             "|".join(sorted(set(ip for ip in self.srcip_list if ip))),
            "severity_dist":            json.dumps(self.severity_dist),
            "rule_id_dist":             json.dumps(self.rule_id_dist),
            "rule_group_dist":          json.dumps(self.rule_group_dist),  # [NEW-1]
            "mitre_tactic":             "|".join(self.mitre_tactic_list),
            "wazuh_alert_ids":          "|".join(self.wazuh_alert_ids),  # [FIX-A] Pipe-separated list
        }


# CompoundMetaAlert (Bucket B)  —  [NEW-2]

@dataclass
class CompoundMetaAlert:
    """
    Merekam semua aktivitas satu agent dalam satu fixed time window.
    Berjalan paralel dengan MetaAlert (Bucket A) — tidak menggantikannya.

    Digunakan untuk: rule_group_entropy (f10), tactic_progression (f11),
    deteksi multi-stage attack yang lintas rule_group.
    """
    compound_id:      int
    agent_id:         str
    agent_name:       str
    window_id:        int
    window_start:     pd.Timestamp
    window_end:       pd.Timestamp
    start_time:       pd.Timestamp
    end_time:         pd.Timestamp
    alert_count:      int         = 0
    max_severity:     int         = 0
    mitre_hit_count:  int         = 0
    rule_groups_seen:   list[str] = field(default_factory=list)
    mitre_tactics_seq:  list[str] = field(default_factory=list)
    srcip_list:         list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        from collections import Counter
        rg_dist = dict(Counter(self.rule_groups_seen))
        return {
            "compound_id":     self.compound_id,
            "agent_id":        self.agent_id,
            "agent_name":      self.agent_name,
            "window_start":    self.window_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "window_end":      self.window_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "start_time":      self.start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "end_time":        self.end_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "duration_sec":    max(0, int((self.end_time - self.start_time).total_seconds())),
            "alert_count":     self.alert_count,
            "max_severity":    self.max_severity,
            "mitre_hit_count": self.mitre_hit_count,
            "n_rule_groups":   len(set(self.rule_groups_seen)),
            "attacker_count":  len(set(ip for ip in self.srcip_list if ip)),
            "attacker_ips":    "|".join(sorted(set(ip for ip in self.srcip_list if ip))),
            "rule_group_dist": json.dumps(rg_dist),
            "mitre_tactic":    "|".join(self.mitre_tactics_seq),
        }


# Builder helpers

def _key_a(row: pd.Series) -> tuple:
    return (str(row["agent_id"]), str(row["rule_groups"]).strip().lower())


def _key_b(row: pd.Series, ts, window_sec: int) -> tuple:
    if not isinstance(ts, pd.Timestamp):
        ts = pd.Timestamp(ts)
    win_id = int(floor(ts.timestamp() / window_sec))
    return (str(row["agent_id"]), win_id)


def _new_meta(meta_id, row, ts, lv, ip, srcip_type, parent_id=None):
    rg      = str(row.get("rule_groups", "unknown")).strip().lower()
    rid     = str(row.get("rule_id", "unknown"))
    crit    = int(row.get("criticality_score", 1))
    mitre   = int(row.get("has_mitre", 0))
    wid     = str(row.get("wazuh_alert_id", ""))  # [FIX-A] Ambil wazuh_alert_id
    ma      = MetaAlert(
        meta_id               = meta_id,
        parent_meta_id        = parent_id,
        agent_id              = str(row.get("agent_id", "unknown")),
        agent_name            = str(row.get("agent_name", "")),
        rule_groups           = rg,
        start_time            = ts,
        end_time              = ts,
        alert_count           = 1,
        max_severity          = lv,
        criticality_score     = crit,
        external_threat_count = 1 if srcip_type == "external" else 0,
        internal_src_count    = 1 if srcip_type == "internal" else 0,
        mitre_hit_count       = mitre,
        srcip_list            = [ip] if ip else [],
        rule_id_dist          = {rid: 1},
        severity_dist         = {str(lv): 1},
        rule_group_dist       = {rg: 1},
        wazuh_alert_ids       = [wid] if wid else [],  # [FIX-A] Simpan ID pertama
    )
    ma._unique_rule_ids = {rid}
    return ma


def _new_compound(compound_id, row, ts, win_id, window_sec, lv, ip):
    win_start = pd.Timestamp(win_id * window_sec, unit="s")
    win_end   = win_start + timedelta(seconds=window_sec)
    rg        = str(row.get("rule_groups", "unknown")).strip().lower()
    tactic    = str(row.get("mitre_tactic", "") or "")
    return CompoundMetaAlert(
        compound_id       = compound_id,
        agent_id          = str(row.get("agent_id", "unknown")),
        agent_name        = str(row.get("agent_name", "")),
        window_id         = win_id,
        window_start      = win_start,
        window_end        = win_end,
        start_time        = ts,
        end_time          = ts,
        alert_count       = 1,
        max_severity      = lv,
        mitre_hit_count   = int(row.get("has_mitre", 0)),
        rule_groups_seen  = [rg],
        mitre_tactics_seq = [t.strip() for t in tactic.split("|") if t.strip()],
        srcip_list        = [ip] if ip else [],
    )


# run_rbta  —  v5

def run_rbta(
    df:                 pd.DataFrame,
    delta_t_minutes:    int   = 15,
    max_window_minutes: int   = 60,
    buffer_size:        int   = 50,
    max_lateness_sec:   float = 10.0,
    enable_adaptive:    bool  = True,
) -> tuple[pd.DataFrame, pd.DataFrame, dict, ElasticWindow, Watermark]:
    """
    RBTA Enhanced v5 — Bucket A (ARR) + Bucket B (behavioral) paralel.

    Returns
    -------
    df_meta         : DataFrame Bucket A — untuk ARR, evaluasi, IF.
    df_compound     : DataFrame Bucket B — untuk feature_engineering f10/f11.
    alert_index_map : { meta_id: [row_index] } — hanya Bucket A.
    elastic         : ElasticWindow.
    wmark           : Watermark.
    """
    # Validate required columns
    required_cols = ["timestamp", "agent_id", "rule_groups", "rule_level"]
    missing_cols = [col for col in required_cols if col not in df.columns]
    if missing_cols:
        available = df.columns.tolist()
        raise KeyError(
            f"DataFrame RBTA missing required columns: {missing_cols}. "
            f"Available: {available}. "
            f"Ensure preprocessing renamed 'timestamp_utc' → 'timestamp' and 'rule_group_primary' → 'rule_groups'"
        )
    
    base_dt      = timedelta(minutes=delta_t_minutes)
    max_win_sec  = max_window_minutes * 60
    compound_sec = delta_t_minutes * 60

    # Pastikan timestamp selalu datetime, bukan string
    if not pd.api.types.is_datetime64_any_dtype(df["timestamp"]):
        df = df.copy()
        _t = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
        try:
            df["timestamp"] = _t.dt.tz_convert(None)
        except Exception:
            df["timestamp"] = _t.apply(
                lambda x: x.replace(tzinfo=None) if not pd.isna(x) else pd.NaT
            )
        df = df.dropna(subset=["timestamp"]).reset_index(drop=True)
    elif pd.api.types.is_datetime64tz_dtype(df["timestamp"]):
        df = df.copy()
        df["timestamp"] = df["timestamp"].dt.tz_convert(None)

    buffer  = OutOfOrderBuffer(k=buffer_size)
    elastic = ElasticWindow(base_dt=base_dt) if enable_adaptive else None
    wmark   = Watermark(max_lateness_sec=max_lateness_sec)

    act_a:   dict[tuple, MetaAlert]         = {}
    act_idx: dict[tuple, list[int]]         = {}
    fin_a:   list[MetaAlert]               = []
    fin_idx: dict[int, list[int]]          = {}
    mid = 1

    act_b:  dict[tuple, CompoundMetaAlert] = {}
    fin_b:  list[CompoundMetaAlert]        = []
    cid = 1

    t0 = time.perf_counter()

    def _close_a(key):
        bucket   = act_a.pop(key)
        idx_list = act_idx.pop(key)
        fin_a.append(bucket)
        fin_idx[bucket.meta_id] = idx_list

    def _process(ts, row, row_idx):
        nonlocal mid, cid

        wmark.advance(ts)
        if wmark.classify(ts) == "late_drop":
            return

        cur_dt     = elastic.update(ts) if elastic else base_dt
        ka         = _key_a(row)
        lv         = int(row.get("rule_level", 0))
        ip         = str(row.get("srcip", "") or "")
        rid        = str(row.get("rule_id", "unknown"))
        stype      = str(row.get("srcip_type", "none"))
        has_mitre  = int(row.get("has_mitre", 0))
        tactic_raw = str(row.get("mitre_tactic", "") or "")
        clean_rg   = str(row.get("rule_groups", "unknown")).strip().lower()

        # Bucket A
        if ka in act_a:
            b   = act_a[ka]
            gap = ts - b.end_time
            dur = (ts - b.start_time).total_seconds()
            if gap <= cur_dt and dur <= max_win_sec:
                b.end_time      = max(b.end_time, ts)
                b.alert_count  += 1
                b.max_severity  = max(b.max_severity, lv)
                if ip:
                    b.srcip_list.append(ip)
                b.rule_id_dist[rid]     = b.rule_id_dist.get(rid, 0) + 1
                b.severity_dist[str(lv)] = b.severity_dist.get(str(lv), 0) + 1
                b.rule_group_dist[clean_rg] = b.rule_group_dist.get(clean_rg, 0) + 1  # [NEW-3]
                b._unique_rule_ids.add(rid)
                # [FIX-A] Simpan wazuh_alert_id
                wid_alert = str(row.get("wazuh_alert_id", "") or "")
                if wid_alert:
                    b.wazuh_alert_ids.append(wid_alert)
                if stype == "external":
                    b.external_threat_count += 1
                elif stype == "internal":
                    b.internal_src_count += 1
                b.mitre_hit_count += has_mitre
                # Akumulasi MITRE tactics dari individual alerts
                if has_mitre and tactic_raw:
                    for t in tactic_raw.split("|"):
                        t = t.strip()
                        if t:
                            b.mitre_tactic_list.append(t)
                act_idx[ka].append(row_idx)
            else:
                is_cont   = (gap <= cur_dt) and (dur > max_win_sec)
                parent_id = b.meta_id if is_cont else None
                _close_a(ka)
                act_a[ka]   = _new_meta(mid, row, ts, lv, ip, stype, parent_id)
                act_idx[ka] = [row_idx]
                mid += 1
        else:
            act_a[ka]   = _new_meta(mid, row, ts, lv, ip, stype)
            act_idx[ka] = [row_idx]
            mid += 1

        # Bucket B
        kb     = _key_b(row, ts, compound_sec)
        win_id = kb[1]
        agent  = str(row.get("agent_id", ""))

        # Tutup bucket B lama untuk agent yang sama yang sudah lewat window
        old_keys = [k for k in list(act_b) if k[0] == agent and k[1] != win_id]
        for ok in old_keys:
            fin_b.append(act_b.pop(ok))

        if kb in act_b:
            cb = act_b[kb]
            cb.alert_count    += 1
            cb.max_severity    = max(cb.max_severity, lv)
            cb.end_time        = max(cb.end_time, ts)
            cb.mitre_hit_count += has_mitre
            cb.rule_groups_seen.append(clean_rg)
            if ip:
                cb.srcip_list.append(ip)
            for t in tactic_raw.split("|"):
                t = t.strip()
                if t:
                    cb.mitre_tactics_seq.append(t)
        else:
            act_b[kb] = _new_compound(cid, row, ts, win_id, compound_sec, lv, ip)
            cid += 1

    # Main loop
    for row_idx, row in df.iterrows():
        ts = row["timestamp"]
        if not isinstance(ts, pd.Timestamp):
            try:
                ts = pd.Timestamp(ts)
            except Exception:
                continue
        buffer.push(ts, (row_idx, row))
        if buffer.is_full:
            old_ts, (oi, or_) = _pop_with_idx(buffer)
            _process(old_ts, or_, oi)

    for ts, (oi, or_) in _drain_with_idx(buffer):
        _process(ts, or_, oi)

    for k in list(act_a.keys()):
        _close_a(k)
    for k in list(act_b.keys()):
        fin_b.append(act_b.pop(k))

    elapsed = (time.perf_counter() - t0) * 1000

    if not fin_a:
        log.warning("RBTA tidak menghasilkan meta-alert. Periksa data input.")
        return pd.DataFrame(), pd.DataFrame(), {}, elastic, wmark

    df_meta = (
        pd.DataFrame([m.to_dict() for m in fin_a])
        .sort_values("start_time")
        .reset_index(drop=True)
    )
    df_compound = (
        pd.DataFrame([c.to_dict() for c in fin_b])
        .sort_values("start_time")
        .reset_index(drop=True)
    ) if fin_b else pd.DataFrame()

    n_raw = len(df)
    n_meta = len(df_meta)
    arr    = (1 - n_meta / n_raw) * 100 if n_raw > 0 else 0.0
    log.info(
        "RBTA v5: raw=%d  meta_A=%d  compound_B=%d  ARR=%.2f%%  t=%.1fms",
        n_raw, n_meta, len(df_compound), arr, elapsed,
    )
    return df_meta, df_compound, fin_idx, elastic, wmark


# Validasi mapping (Bucket A)

def validate_mapping(df_raw, df_meta, alert_index_map):
    all_idx     = [i for lst in alert_index_map.values() for i in lst]
    total       = len(all_idx)
    unique      = len(set(all_idx))
    overlap     = total - unique
    map_ids     = set(alert_index_map.keys())
    df_ids      = set(df_meta["meta_id"].tolist()) if "meta_id" in df_meta.columns else set()
    mismatch    = []
    if "meta_id" in df_meta.columns and "alert_count" in df_meta.columns:
        for _, row in df_meta.iterrows():
            mid = row["meta_id"]
            if mid in alert_index_map:
                exp = len(alert_index_map[mid])
                act = row["alert_count"]
                if exp != act:
                    mismatch.append({"meta_id": mid, "expected": exp, "actual": act})
    ok = (overlap == 0 and not (map_ids - df_ids) and not (df_ids - map_ids) and not mismatch)
    log.info(
        "Validasi: total=%d  overlap=%d  mismatch=%d  -> %s",
        total, overlap, len(mismatch), "LULUS" if ok else "GAGAL",
    )
    return {"ok": ok, "total_mapped": total, "total_raw": len(df_raw),
            "unique_mapped": unique, "overlap_count": overlap, "mismatch": mismatch}


# add_if_features (f1-f9)

def add_if_features(df_meta: pd.DataFrame) -> pd.DataFrame:
    """Validasi 9 fitur f1-f9. f10-f13 ditangani feature_engineering.py."""
    df = df_meta.copy()
    df["duration_sec"] = df["duration_sec"].clip(lower=0)

    if "rule_group_severity_enc" not in df.columns:
        df["rule_groups"] = df["rule_groups"].astype(str).str.strip().str.lower()
        df["rule_group_severity_enc"] = (
            df["rule_groups"].map(RULE_GROUP_SEVERITY_ENC).fillna(DEFAULT_GROUP_ENC).astype(int)
        )

    if "agent_criticality" not in df.columns:
        df["agent_criticality"] = (
            df["agent_name"].astype(str).str.strip().str.lower()
            .map(AGENT_CRITICALITY).fillna(DEFAULT_CRITICALITY).astype(int)
        )
    else:
        df["agent_criticality"] = (
            pd.to_numeric(df["agent_criticality"], errors="coerce")
            .fillna(DEFAULT_CRITICALITY).clip(1, 4).astype(int)
        )

    if "hour_of_day" not in df.columns:
        df["start_time"] = pd.to_datetime(df["start_time"], errors="coerce")
        df["hour_of_day"] = df["start_time"].dt.hour

    for col in ("unique_rules_triggered", "mitre_hit_count"):
        if col not in df.columns:
            log.warning("Kolom %s tidak ada — di-set 0.", col)
            df[col] = 0

    for col in FEATURE_COLS_V5:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(int)

    df["rule_groups"] = df["rule_groups"].astype(str).str.strip().str.lower()
    return df


def load_alerts(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    for col in ("start_time", "end_time"):
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors="coerce").dt.tz_localize(None)
    return df


# Entry point

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    sys.path.insert(0, ".")
    from etl.preprocessing_01 import load_and_prepare

    csv_path = sys.argv[1] if len(sys.argv) > 1 else "data/rbta_ready_all.csv"
    df_raw   = load_and_prepare(csv_path)

    df_meta, df_compound, idx_map, elastic, wmark = run_rbta(
        df_raw, delta_t_minutes=15, buffer_size=50, enable_adaptive=True,
    )
    df_meta = add_if_features(df_meta)
    log.info("df_meta:\n%s", df_meta[FEATURE_COLS_V5].head(3).to_string())
    if not df_compound.empty:
        log.info("df_compound:\n%s", df_compound.head(3).to_string())

    result = validate_mapping(df_raw, df_meta, idx_map)
    if not result["ok"]:
        log.error("Mapping GAGAL!")
        sys.exit(1)
    log.info("RBTA v5 lulus validasi.")