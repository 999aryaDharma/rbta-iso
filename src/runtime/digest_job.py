"""Daily digest Telegram (T9): top-10 kelompok NOISE_HIGH 24 jam terakhir.

Lapisan penyajian saja: tidak mengubah decision/action. NOISE_HIGH (action DAILY_DIGEST) adalah
MetaAlert berseverity tinggi dengan skor di bawah θ; digest merangkumnya per
(agent, rule_group_primary) agar analyst bisa meninjau sekali sehari.

Urutan kelompok: jumlah MetaAlert menurun, lalu total alert menurun, lalu nama (deterministik).
Dedup per tanggal WITA lewat tabel durable ``digest_log``; mode dry-run/hold dan throttle
mengikuti TelegramDispatcher yang sama dengan eskalasi.
"""

from datetime import datetime, timedelta, timezone
from html import escape
import json
import logging
import sqlite3
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

from src.runtime.evidence_export import WITA, DailyJob, parse_hhmm

logger = logging.getLogger(__name__)

DIGEST_LIMIT = 10


def build_digest_groups(history_db, start_iso: str, end_iso: str, limit: int = DIGEST_LIMIT) -> List[Dict[str, Any]]:
    """Kelompok NOISE_HIGH dengan end_time di [start_iso, end_iso), diurutkan deterministik."""
    with sqlite3.connect(history_db) as conn:
        rows = conn.execute(
            "SELECT scored_data FROM finalized_history"
            " WHERE json_extract(scored_data, '$.decision') = 'NOISE_HIGH'"
            " AND json_extract(scored_data, '$.end_time') >= ? AND json_extract(scored_data, '$.end_time') < ?",
            (start_iso, end_iso),
        ).fetchall()
    groups: Dict[tuple, Dict[str, Any]] = {}
    for (raw,) in rows:
        m = json.loads(raw)
        agent = m.get("agent_name") if m.get("agent_name") not in (None, "", "unknown") else m.get("agent_id")
        key = (str(agent), str(m.get("rule_group_primary")))
        g = groups.setdefault(key, {
            "agent": key[0], "agent_id": m.get("agent_id"), "rule_group_primary": key[1],
            "meta_alerts": 0, "total_alerts": 0, "max_severity": 0, "first": m["start_time"], "last": m["end_time"],
        })
        g["meta_alerts"] += 1
        g["total_alerts"] += int(m.get("alert_count") or 0)
        g["max_severity"] = max(g["max_severity"], int(m.get("max_severity") or 0))
        g["first"] = min(g["first"], m["start_time"])
        g["last"] = max(g["last"], m["end_time"])
    ordered = sorted(groups.values(), key=lambda g: (-g["meta_alerts"], -g["total_alerts"], g["agent"], g["rule_group_primary"]))
    return ordered[:limit]


def _wita(iso: str) -> str:
    return datetime.fromisoformat(iso).astimezone(WITA).strftime("%d/%m %H:%M")


def format_digest(groups: List[Dict[str, Any]], day_label: str, dashboard_url: Optional[str] = None) -> str:
    """HTML Telegram (sudah di-escape) untuk digest satu hari."""
    lines = [f"<b>DAILY DIGEST · NOISE_HIGH · {escape(day_label)}</b>", "24 jam terakhir, top kelompok (agent · rule group):", ""]
    if not groups:
        lines.append("Tidak ada MetaAlert NOISE_HIGH.")
    for i, g in enumerate(groups, 1):
        lines.append(
            f"{i}. <code>{escape(g['agent'])} · {escape(g['rule_group_primary'])}</code>\n"
            f"   {g['meta_alerts']} meta-alert · {g['total_alerts']} alert · level max {g['max_severity']}/15\n"
            f"   {_wita(g['first'])}–{_wita(g['last'])} WITA"
        )
        if dashboard_url:
            query = urlencode({"decision": "NOISE_HIGH", "search": g["rule_group_primary"]})
            lines.append(f"   {escape(dashboard_url.rstrip('/'))}/meta-alerts?{escape(query)}")
    lines += ["", "<i>NOISE_HIGH = severity tinggi tetapi skor di bawah ambang; tinjauan harian, bukan eskalasi.</i>"]
    return "\n".join(lines)


def _ensure_log(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS digest_log (digest_date TEXT PRIMARY KEY, mode TEXT NOT NULL, groups INTEGER NOT NULL,"
        " at TEXT NOT NULL)"
    )


def run_digest(state_manager: Any, dispatcher: Any, now: datetime, dashboard_url: Optional[str] = None) -> str:
    """Kirim digest untuk tanggal WITA ``now`` sekali saja. Hasil: sent|dry_run|duplicate|held|failed."""
    digest_date = now.astimezone(WITA).date().isoformat()
    db = state_manager.history_db_path
    with sqlite3.connect(db) as conn:
        _ensure_log(conn)
        if conn.execute("SELECT 1 FROM digest_log WHERE digest_date = ?", (digest_date,)).fetchone():
            return "duplicate"
    end = now.astimezone(timezone.utc)
    groups = build_digest_groups(db, (end - timedelta(hours=24)).isoformat(), end.isoformat())
    result = dispatcher.send_text(format_digest(groups, digest_date, dashboard_url), kind=f"digest:{digest_date}")
    if result in ("sent", "dry_run"):
        with sqlite3.connect(db) as conn:
            _ensure_log(conn)
            conn.execute(
                "INSERT OR IGNORE INTO digest_log (digest_date, mode, groups, at) VALUES (?, ?, ?, ?)",
                (digest_date, result, len(groups), datetime.now(timezone.utc).isoformat()),
            )
    logger.info("Daily digest %s: %s (%d groups)", digest_date, result, len(groups))
    return result


def make_digest_job(service: Any, dispatcher: Any, at: str = "07:30", dashboard_url: Optional[str] = None) -> DailyJob:
    """Job harian digest. DailyJob memberi ``hari kemarin``; digest memakai waktu jalan sekarang."""

    def task(_day) -> None:
        run_digest(service.state_manager, dispatcher, datetime.now(timezone.utc), dashboard_url)

    def is_done(_day) -> bool:
        with sqlite3.connect(service.state_manager.history_db_path) as conn:
            _ensure_log(conn)
            today = datetime.now(WITA).date().isoformat()
            return conn.execute("SELECT 1 FROM digest_log WHERE digest_date = ?", (today,)).fetchone() is not None

    return DailyJob("daily-digest", task, parse_hhmm(at), is_done=is_done)
