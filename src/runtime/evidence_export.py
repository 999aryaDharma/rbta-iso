"""Ekspor bukti harian live (T6) untuk Bab IV: CSV deskriptif per hari WITA.

Semua angka dihitung dari state durable live saat ekspor; tidak ada konstanta hasil.
Definisi (hari = tanggal kalender Asia/Makassar, batas [00:00, 24:00) WITA):

* ``raw_alerts``: alert unik di raw evidence live dengan event ``timestamp`` di hari itu.
* ``excluded_alerts``: alert agen yang dikecualikan (T4) dengan event time di hari itu.
* ``meta_alerts`` dan hitungan aksi: MetaAlert final dengan ``end_time`` di hari itu.
  ``n_suppress`` sudah termasuk ``n_contextual`` (CONTEXTUAL_ANOMALY -> SUPPRESS).
* ``arr`` = (1 - meta_alerts / raw_alerts) * 100, reduksi unit triase, bukan akurasi deteksi.
* ``quarantined``: ID yang pertama kali dikarantina (first_seen) di hari itu.
* ``event_lag_*``: ingested_at - timestamp per alert (keterlambatan ingest).
* ``finalize_latency_*`` / ``dispatch_latency_*``: event->finalize dan finalize->Telegram
  terkirim (T7) untuk MetaAlert yang difinalkan di hari itu.
* ``worker_restarts``: jumlah start live worker di hari itu.

File ditulis ulang secara atomik dengan baris tanggal yang sama diganti, sehingga ekspor ulang
untuk tanggal yang sama idempoten.
"""

import csv
from datetime import date, datetime, time, timedelta, timezone
import json
import logging
import os
from pathlib import Path
import sqlite3
import threading
from typing import Any, Callable, Dict, Iterable, List, Optional
from zoneinfo import ZoneInfo

import numpy as np
import pandas as pd

from src.features.extractor import FEATURE_COLUMNS

logger = logging.getLogger(__name__)

WITA = ZoneInfo("Asia/Makassar")
SUMMARY_FILE = "daily_summary.csv"
PER_AGENT_FILE = "daily_per_agent.csv"
QUANTILE_FILE = "feature_quantiles_live.csv"
EVIDENCE_FILES = frozenset({SUMMARY_FILE, PER_AGENT_FILE, QUANTILE_FILE})

SUMMARY_COLUMNS = [
    "date", "model_version", "model_sha256", "raw_alerts", "excluded_alerts", "meta_alerts", "arr",
    "n_escalate", "n_digest", "n_suppress", "n_contextual", "quarantined",
    "event_lag_p50", "event_lag_p95", "finalize_latency_p50", "finalize_latency_p95",
    "dispatch_latency_p50", "dispatch_latency_p95", "worker_restarts",
]
PER_AGENT_COLUMNS = ["date", "agent", "raw", "meta", "escalate", "digest", "suppress"]
QUANTILE_COLUMNS = ["date", "feature", "n", "q1", "median", "q3", "p95"]


def wita_day_bounds(day: date) -> tuple:
    """Batas UTC ISO [start, end) untuk satu hari kalender WITA."""
    start = datetime.combine(day, time(0), WITA).astimezone(timezone.utc)
    return start.isoformat(), (start + timedelta(days=1)).isoformat()


def _pct(values: List[float], q: float) -> Optional[float]:
    return float(np.percentile(values, q)) if values else None


def _agent_label(agent_name: Optional[str], agent_id: Optional[str]) -> str:
    return str(agent_name if agent_name and agent_name != "unknown" else agent_id or "unknown")


def load_source_state(history_db: Path) -> Dict[str, Any]:
    """Source checkpoint dari snapshot SQLite (dipakai CLI tanpa service yang hidup)."""
    with sqlite3.connect(history_db) as conn:
        row = conn.execute("SELECT payload FROM runtime_snapshot WHERE id = 1").fetchone()
    return dict(json.loads(row[0]).get("source_checkpoint", {})) if row else {}


def collect_day(
    state_manager: Any,
    evidence_db: Optional[Path],
    day: date,
    model_identity: Optional[Dict[str, Any]] = None,
    source_state: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Hitung baris summary, per-agen, dan kuantil fitur untuk satu hari WITA."""
    start, end = wita_day_bounds(day)
    day_str = day.isoformat()

    with sqlite3.connect(state_manager.history_db_path) as conn:
        metas = [
            json.loads(r[0]) for r in conn.execute(
                "SELECT scored_data FROM finalized_history"
                " WHERE json_extract(scored_data, '$.end_time') >= ? AND json_extract(scored_data, '$.end_time') < ?",
                (start, end),
            )
        ]
        excluded = conn.execute(
            "SELECT COUNT(*) FROM excluded_alerts WHERE event_time >= ? AND event_time < ?", (start, end)
        ).fetchone()[0]
        quarantined = conn.execute(
            "SELECT COUNT(*) FROM quarantined_alerts WHERE first_seen >= ? AND first_seen < ?", (start, end)
        ).fetchone()[0]

    raw_rows: List[tuple] = []
    if evidence_db is not None and Path(evidence_db).exists():
        with sqlite3.connect(evidence_db) as conn:
            raw_rows = conn.execute(
                "SELECT agent_name, agent_id, timestamp, ingested_at FROM raw_alert_evidence"
                " WHERE timestamp >= ? AND timestamp < ?",
                (start, end),
            ).fetchall()

    lags = [
        (datetime.fromisoformat(ing) - datetime.fromisoformat(ts)).total_seconds()
        for _, _, ts, ing in raw_rows if ing
    ]
    latency = state_manager.latency_summary(start, end)
    starts = [s for s in (source_state or {}).get("live_worker_start_log") or [] if isinstance(s, str)]
    restarts = sum(1 for s in starts if start <= datetime.fromisoformat(s).astimezone(timezone.utc).isoformat() < end)

    actions = [m.get("action") for m in metas]
    raw_n, meta_n = len(raw_rows), len(metas)
    versions = sorted({str(m.get("model_version")) for m in metas})
    identity = model_identity or {}
    if not versions:
        version, sha = identity.get("version", ""), identity.get("sha256", "")
    elif versions == [identity.get("version")]:
        version, sha = versions[0], identity.get("sha256", "")
    else:
        # Hari itu memuat MetaAlert dari model lain: sha model aktif tidak mewakili.
        version, sha = ";".join(versions), ""

    summary = {
        "date": day_str, "model_version": version, "model_sha256": sha,
        "raw_alerts": raw_n, "excluded_alerts": int(excluded), "meta_alerts": meta_n,
        "arr": (1.0 - meta_n / raw_n) * 100.0 if raw_n else None,
        "n_escalate": actions.count("ESCALATE"), "n_digest": actions.count("DAILY_DIGEST"),
        "n_suppress": actions.count("SUPPRESS"),
        "n_contextual": sum(1 for m in metas if m.get("decision") == "CONTEXTUAL_ANOMALY"),
        "quarantined": int(quarantined),
        "event_lag_p50": _pct(lags, 50), "event_lag_p95": _pct(lags, 95),
        "finalize_latency_p50": latency.get("event_to_finalize_p50"),
        "finalize_latency_p95": latency.get("event_to_finalize_p95"),
        "dispatch_latency_p50": latency.get("finalize_to_sent_p50"),
        "dispatch_latency_p95": latency.get("finalize_to_sent_p95"),
        "worker_restarts": restarts,
    }

    per_agent: Dict[str, Dict[str, Any]] = {}

    def _row(agent: str) -> Dict[str, Any]:
        return per_agent.setdefault(agent, {
            "date": day_str, "agent": agent, "raw": 0, "meta": 0, "escalate": 0, "digest": 0, "suppress": 0,
        })

    for agent_name, agent_id, _, _ in raw_rows:
        _row(_agent_label(agent_name, agent_id))["raw"] += 1
    for m in metas:
        row = _row(_agent_label(m.get("agent_name"), m.get("agent_id")))
        row["meta"] += 1
        key = {"ESCALATE": "escalate", "DAILY_DIGEST": "digest", "SUPPRESS": "suppress"}.get(m.get("action"))
        if key:
            row[key] += 1

    quantiles: List[Dict[str, Any]] = []
    if metas:
        features = pd.DataFrame([m.get("seven_features", {}) for m in metas], columns=list(FEATURE_COLUMNS))
        for feature in FEATURE_COLUMNS:
            col = features[feature].dropna()
            quantiles.append({
                "date": day_str, "feature": feature, "n": int(len(col)),
                "q1": float(col.quantile(0.25)), "median": float(col.quantile(0.50)),
                "q3": float(col.quantile(0.75)), "p95": float(col.quantile(0.95)),
            })

    return {
        "summary": summary,
        "per_agent": [per_agent[k] for k in sorted(per_agent)],
        "quantiles": quantiles,
    }


def _replace_day_rows(path: Path, columns: List[str], rows: Iterable[Dict[str, Any]], day_str: str) -> None:
    """Tulis ulang CSV secara atomik: baris tanggal ``day_str`` diganti dengan ``rows``."""
    kept: List[Dict[str, Any]] = []
    if path.exists():
        with path.open(newline="", encoding="utf-8") as f:
            kept = [r for r in csv.DictReader(f) if r.get("date") != day_str]
    merged = kept + [{c: ("" if r.get(c) is None else r.get(c)) for c in columns} for r in rows]
    merged.sort(key=lambda r: str(r.get("date")))
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(merged)
    os.replace(tmp, path)


def export_day(
    state_manager: Any,
    evidence_db: Optional[Path],
    out_dir: Path,
    day: date,
    model_identity: Optional[Dict[str, Any]] = None,
    source_state: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Hitung lalu tulis ketiga CSV untuk ``day`` (summary terakhir, sebagai penanda selesai)."""
    data = collect_day(state_manager, evidence_db, day, model_identity, source_state)
    out_dir.mkdir(parents=True, exist_ok=True)
    day_str = day.isoformat()
    _replace_day_rows(out_dir / PER_AGENT_FILE, PER_AGENT_COLUMNS, data["per_agent"], day_str)
    _replace_day_rows(out_dir / QUANTILE_FILE, QUANTILE_COLUMNS, data["quantiles"], day_str)
    _replace_day_rows(out_dir / SUMMARY_FILE, SUMMARY_COLUMNS, [data["summary"]], day_str)
    return data


def exported_dates(out_dir: Path) -> set:
    path = out_dir / SUMMARY_FILE
    if not path.exists():
        return set()
    with path.open(newline="", encoding="utf-8") as f:
        return {r["date"] for r in csv.DictReader(f)}


def parse_hhmm(value: str) -> time:
    hour, minute = (int(x) for x in str(value).strip().split(":"))
    return time(hour, minute)


class DailyJob:
    """Thread harian sederhana: jalankan ``task(hari_kemarin_WITA)`` pada jam HH:MM WITA.

    Saat start, bila jadwal hari ini sudah lewat dan ``is_done(kemarin)`` False, task langsung
    dijalankan (catch-up setelah restart). Error task dicatat dan tidak menghentikan thread.
    """

    def __init__(
        self,
        name: str,
        task: Callable[[date], Any],
        at: time,
        is_done: Callable[[date], bool] = lambda _day: False,
        now_fn: Callable[[], datetime] = lambda: datetime.now(WITA),
    ) -> None:
        self.name = name
        self._task = task
        self._at = at
        self._is_done = is_done
        self._now = now_fn
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.last_run_day: Optional[date] = None
        self.last_error: Optional[str] = None

    def run_for(self, day: date) -> None:
        try:
            self._task(day)
            self.last_run_day = day
            self.last_error = None
        except Exception as exc:  # job harian tidak boleh mematikan service
            self.last_error = str(exc)
            logger.error("%s for %s failed: %s", self.name, day, exc)

    def seconds_until_next(self) -> float:
        now = self._now().astimezone(WITA)
        target = datetime.combine(now.date(), self._at, WITA)
        if target <= now:
            target += timedelta(days=1)
        return max(1.0, (target - now).total_seconds())

    def _loop(self) -> None:
        now = self._now().astimezone(WITA)
        yesterday = now.date() - timedelta(days=1)
        if now.time() >= self._at and not self._is_done(yesterday):
            self.run_for(yesterday)
        while not self._stop.wait(self.seconds_until_next()):
            self.run_for(self._now().astimezone(WITA).date() - timedelta(days=1))

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name=self.name, daemon=True)
        self._thread.start()

    def stop(self, timeout_sec: float = 10.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout_sec)
        self._thread = None


def make_evidence_export_job(service: Any, out_dir: Path, model_identity: Optional[Dict[str, Any]], at: time) -> DailyJob:
    """Job ekspor bukti harian untuk service live yang sedang berjalan."""
    store = getattr(service, "raw_evidence_store", None)

    def task(day: date) -> None:
        if store is not None and hasattr(store, "flush"):
            store.flush()
        export_day(
            service.state_manager,
            getattr(store, "db_path", None),
            out_dir,
            day,
            model_identity=model_identity,
            source_state=service.get_live_source_state(),
        )
        logger.info("Live evidence exported for %s -> %s", day, out_dir)

    return DailyJob("evidence-export", task, at, is_done=lambda d: d.isoformat() in exported_dates(out_dir))
