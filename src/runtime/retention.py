"""Retensi data live (T12): pangkas raw evidence, seen_alert_ids, dan arsip live lama.

Cutoff = sekarang - RBTA_RETENTION_DAYS (default 90; 0 = nonaktif).

* raw evidence: baris dengan event ``timestamp`` < cutoff.
* seen_alert_ids: baris dengan ``inserted_at`` < cutoff. Karena alert di-ingest setelah event-nya,
  setiap ID dengan event time >= cutoff pasti tetap tersimpan. Agar ID yang dipangkas tidak
  di-ingest ulang oleh rekonsiliasi penuh (yang menyapu seluruh retensi Indexer), coordinator
  live melewati kandidat dengan event time < cutoff dan menghitungnya sebagai
  ``retention_expired`` (bukan diproses ulang menjadi MetaAlert ganda).
* arsip live ``live-YYYYMMDD.jsonl`` dengan tanggal < tanggal cutoff (UTC).
* MetaAlert final (finalized_history), label analyst, dan CSV bukti TIDAK dipangkas.

VACUUM dijalankan terjadwal (default hari Minggu WITA) setelah pemangkasan.
"""

from datetime import datetime, timedelta, timezone
import logging
import os
from pathlib import Path
import shutil
import sqlite3
from typing import Any, Dict, Optional

from src.runtime.evidence_export import WITA, DailyJob, parse_hhmm

logger = logging.getLogger(__name__)

DEFAULT_RETENTION_DAYS = 90
DISK_WARN_PCT = 80.0


def retention_days_from_env(env_map) -> int:
    raw = str(env_map.get("RBTA_RETENTION_DAYS") or DEFAULT_RETENTION_DAYS).strip()
    days = int(raw)
    if days < 0:
        raise ValueError(f"RBTA_RETENTION_DAYS must be >= 0, got '{raw}'")
    return days


def retention_cutoff(now: datetime, days: int) -> Optional[datetime]:
    return now.astimezone(timezone.utc) - timedelta(days=days) if days > 0 else None


def disk_usage(path: Path) -> Optional[Dict[str, Any]]:
    """Pemakaian disk volume yang memuat ``path`` (None bila path tidak ada)."""
    try:
        usage = shutil.disk_usage(path)
    except OSError:
        return None
    used_pct = usage.used / usage.total * 100.0 if usage.total else 0.0
    return {"total_bytes": usage.total, "used_bytes": usage.used, "free_bytes": usage.free,
            "used_pct": round(used_pct, 1), "warning": used_pct > DISK_WARN_PCT}


def prune(state_manager: Any, evidence_store: Any, archive_dir: Optional[Path], now: datetime, days: int,
          vacuum: bool = False) -> Dict[str, Any]:
    """Jalankan satu putaran retensi. Mengembalikan jumlah yang dihapus per jenis."""
    cutoff = retention_cutoff(now, days)
    result: Dict[str, Any] = {"cutoff": cutoff.isoformat() if cutoff else None, "raw_evidence": 0,
                              "seen_alert_ids": 0, "archive_files": 0, "vacuumed": False}
    if cutoff is None:
        return result
    if evidence_store is not None:
        result["raw_evidence"] = evidence_store.prune_older_than(cutoff.isoformat())
    with sqlite3.connect(state_manager.history_db_path) as conn:
        # inserted_at memakai format SQLite datetime('now'): 'YYYY-MM-DD HH:MM:SS' UTC.
        cur = conn.execute("DELETE FROM seen_alert_ids WHERE inserted_at < ?", (cutoff.strftime("%Y-%m-%d %H:%M:%S"),))
        result["seen_alert_ids"] = int(cur.rowcount or 0)
        conn.commit()
    if archive_dir is not None and Path(archive_dir).is_dir():
        cutoff_day = cutoff.strftime("%Y%m%d")
        for path in Path(archive_dir).glob("live-*.jsonl"):
            day = path.stem[len("live-"):]
            if len(day) == 8 and day.isdigit() and day < cutoff_day:
                path.unlink()
                result["archive_files"] += 1
    if vacuum:
        if evidence_store is not None:
            evidence_store.vacuum()
        with sqlite3.connect(state_manager.history_db_path) as conn:
            conn.execute("VACUUM")
        result["vacuumed"] = True
    logger.info("Retention pass: %s", result)
    return result


def make_retention_job(service: Any, archive_dir: Optional[Path], days: int, at: str = "03:30",
                       vacuum_weekday: int = 6) -> DailyJob:
    """Job harian retensi; VACUUM pada ``vacuum_weekday`` (0 = Senin ... 6 = Minggu, WITA)."""

    def task(_day) -> None:
        now = datetime.now(timezone.utc)
        prune(service.state_manager, getattr(service, "raw_evidence_store", None), archive_dir, now, days,
              vacuum=now.astimezone(WITA).weekday() == vacuum_weekday)

    return DailyJob("retention", task, parse_hhmm(at))


def archive_dir_for(env_map) -> Optional[Path]:
    raw = (env_map.get("RBTA_LIVE_ARCHIVE_DIR") or os.environ.get("RBTA_LIVE_ARCHIVE_DIR") or "").strip()
    return Path(raw) if raw else None
