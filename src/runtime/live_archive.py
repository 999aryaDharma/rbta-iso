"""Pengarsip alert live (best effort): menulis dataset replay JSONL mentah.

Setiap alert live yang berhasil di-ingest dicatat sebagai satu objek JSON ringkas per
baris di ``data/archive/live-YYYYMMDD.jsonl`` (rotasi harian menurut tanggal UTC
event-time), sehingga aliran live bisa di-replay nanti sebagai dataset deterministik:
setiap baris diterima oleh :func:`src.etl.wazuh_canonicalizer.canonicalize_wazuh_alert`.

Live poller membuang hit OpenSearch asli setelah kanonisasi, jadi record arsip disusun
ulang dari :class:`CanonicalRawAlert` beserta metadata yang ikut tersimpan (deskripsi/group
rule, location, full_log, decoder, manager, data, index sumber/id dokumen). Hasilnya
setara secara kanonis (alert hasil kanonisasi ulang setara per field), bukan identik per byte.

Kebijakan kegagalan: pengarsipan tidak boleh merusak ingestion live. Semua entry point
publik menelan error I/O, mencatat log level warning, menaikkan counter ``failed``,
dan mengembalikan hasil degradasi (``None`` / ``0``).
"""

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import threading
from typing import Any, Dict, List, Mapping, Optional, Union

from src.contracts.raw_alert import CanonicalRawAlert
from src.runtime.json_safe import deterministic_json_dumps, to_json_safe

logger = logging.getLogger(__name__)

DEFAULT_ARCHIVE_DIR = "data/archive"

_stats_lock = threading.Lock()
_stats: Dict[str, Any] = {"archived": 0, "failed": 0, "last_error": None}


def get_stats() -> Dict[str, Any]:
    """Kembalikan snapshot counter arsip (archived, failed, last_error)."""
    with _stats_lock:
        return dict(_stats)


def _bump(archived: int = 0, failed: int = 0, error: Optional[str] = None) -> None:
    with _stats_lock:
        _stats["archived"] += archived
        _stats["failed"] += failed
        if error is not None:
            _stats["last_error"] = error


def archive_enabled_from_env() -> bool:
    """Baca saklar pengarsipan (default False agar replay/demo tidak terpengaruh)."""
    return os.environ.get("RBTA_LIVE_ARCHIVE_ENABLED", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def archive_dir_from_env(default: Union[str, Path] = DEFAULT_ARCHIVE_DIR) -> Path:
    """Baca override direktori arsip (default ``data/archive``)."""
    raw = os.environ.get("RBTA_LIVE_ARCHIVE_DIR", "")
    return Path(raw.strip()) if raw.strip() else Path(default)


def _meta(alert: CanonicalRawAlert) -> Dict[str, Any]:
    meta = alert.metadata
    return dict(meta) if isinstance(meta, Mapping) else {}


def build_archive_record(alert: CanonicalRawAlert) -> Dict[str, Any]:
    """Susun ulang dict raw alert Wazuh yang kompatibel untuk replay dari alert kanonis.

    Mengembalikan envelope hit OpenSearch (``{_index, _id, _source[, sort]}``) bila metadata
    kanonis membawa lineage sumber, selain itu body alert biasa. Kedua bentuk diterima
    ``canonicalize_wazuh_alert``.
    """
    meta = _meta(alert)
    safe = to_json_safe(meta)

    rule: Dict[str, Any] = {"id": alert.rule_id, "level": alert.rule_level}
    description = safe.get("rule_description")
    if description:
        rule["description"] = description
    groups = safe.get("rule_groups_all")
    if isinstance(groups, (list, tuple)) and groups:
        rule["groups"] = list(groups)
    if alert.mitre_tactics:
        rule.setdefault("mitre", {})["tactic"] = list(alert.mitre_tactics)

    body: Dict[str, Any] = {
        "id": alert.wazuh_alert_id,
        "timestamp": alert.timestamp.isoformat(),
        "rule": rule,
        "agent": {"id": alert.agent_id, "name": alert.agent_name},
    }

    data_block = safe.get("data")
    if isinstance(data_block, dict):
        body["data"] = dict(data_block)
    if alert.srcip:
        data = body.setdefault("data", {})
        if isinstance(data, dict):
            data.setdefault("srcip", alert.srcip)
        body.setdefault("srcip", alert.srcip)

    for key in ("location", "full_log", "decoder", "manager"):
        value = safe.get(key)
        if value not in (None, ""):
            body[key] = value

    source_index = safe.get("source_index")
    source_doc_id = safe.get("source_document_id")
    if source_index or source_doc_id:
        envelope: Dict[str, Any] = {"_source": body}
        if source_index:
            envelope["_index"] = source_index
        if source_doc_id:
            envelope["_id"] = source_doc_id
        if safe.get("source_sort") is not None:
            envelope["sort"] = safe.get("source_sort")
        return envelope
    return body


def _event_time(alert: CanonicalRawAlert) -> datetime:
    ts = alert.timestamp
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def _daily_path(archive_dir: Union[str, Path], event_time: datetime) -> Path:
    day = event_time.astimezone(timezone.utc).strftime("%Y%m%d")
    return Path(archive_dir) / f"live-{day}.jsonl"


def _append_line(path: Path, line: str) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            try:
                handle.flush()
                os.fsync(handle.fileno())
            except OSError:
                pass
        return True
    except Exception as exc:  # jangan sampai merambat ke siklus live
        logger.warning("Live archive write failed for '%s': %s", path, exc)
        _bump(failed=1, error=str(exc))
        return False


def append_alert(
    alert: CanonicalRawAlert,
    archive_dir: Union[str, Path],
    event_time: Optional[datetime] = None,
) -> Optional[Path]:
    """Tambahkan satu alert ke file arsip harian. Tidak pernah error; None bila gagal."""
    try:
        record = build_archive_record(alert)
        line = deterministic_json_dumps(record)
        path = _daily_path(archive_dir, event_time or _event_time(alert))
        if _append_line(path, line):
            _bump(archived=1)
            return path
        return None
    except Exception as exc:  # defensif: proses build juga tidak boleh merusak ingestion
        logger.warning("Live archive record build failed for '%s': %s", alert.wazuh_alert_id, exc)
        _bump(failed=1, error=str(exc))
        return None


def append_alerts(
    alerts: List[CanonicalRawAlert],
    archive_dir: Union[str, Path],
) -> int:
    """Tambahkan satu batch berurutan (event_time, alert_id), rotasi per hari UTC. Tidak pernah error."""
    try:
        ordered = sorted(alerts, key=lambda a: (_event_time(a), a.wazuh_alert_id))
    except Exception as exc:
        logger.warning("Live archive batch sort failed: %s", exc)
        _bump(failed=1, error=str(exc))
        return 0
    written = 0
    for alert in ordered:
        if append_alert(alert, archive_dir) is not None:
            written += 1
    return written
