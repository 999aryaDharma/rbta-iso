"""Antrean review analyst (T8): semua ESCALATE + sampel acak 5% SUPPRESS dan 5% DAILY_DIGEST per hari.

Sampel deterministik: untuk hari D (WITA, berdasarkan end_time MetaAlert) ID diurutkan lalu diambil
``ceil(5% x n)`` dengan ``random.Random(f"{D}:{action}")``, sehingga siapa pun bisa mereproduksi
sampel yang sama. Populasi hari D baru stabil setelah hari itu selesai (MetaAlert yang difinalkan
belakangan bisa menambah populasi).

Batas klaim: verdict adalah label analyst pada sampel, bukan ground truth seluruh korpus.
precision@ESCALATE hanya dihitung atas ESCALATE yang sudah dilabel.
"""

from datetime import date
import json
import math
import random
import sqlite3
from typing import Any, Dict, Iterable, List, Optional

from src.runtime.evidence_export import wita_day_bounds

VERDICTS = ("incident", "actionable_benign", "noise")
SAMPLE_RATE = 0.05
QUEUE_REASONS = {"ESCALATE": "ESCALATE", "SUPPRESS": "SAMPLE_SUPPRESS", "DAILY_DIGEST": "SAMPLE_DIGEST"}


def _day_metas(history_db, day: date) -> List[Dict[str, Any]]:
    start, end = wita_day_bounds(day)
    with sqlite3.connect(history_db) as conn:
        rows = conn.execute(
            "SELECT scored_data FROM finalized_history"
            " WHERE json_extract(scored_data, '$.end_time') >= ? AND json_extract(scored_data, '$.end_time') < ?"
            " ORDER BY meta_id",
            (start, end),
        ).fetchall()
    return [json.loads(r[0]) for r in rows]


def sample_ids(ids: List[int], day: date, action: str, rate: float = SAMPLE_RATE) -> List[int]:
    """Sampel deterministik ceil(rate x n) dari ``ids`` dengan seed tanggal + action."""
    population = sorted(ids)
    if not population:
        return []
    k = min(len(population), math.ceil(rate * len(population)))
    return sorted(random.Random(f"{day.isoformat()}:{action}").sample(population, k))


def build_review_queue(state_manager: Any, days: Iterable[date]) -> List[Dict[str, Any]]:
    """Item antrean review untuk hari-hari ``days`` beserta verdict yang sudah ada."""
    verdicts = state_manager.verdict_map()
    items: List[Dict[str, Any]] = []
    for day in days:
        metas = _day_metas(state_manager.history_db_path, day)
        picked = {m["meta_id"] for m in metas if m.get("action") == "ESCALATE"}
        for action in ("SUPPRESS", "DAILY_DIGEST"):
            picked.update(sample_ids([m["meta_id"] for m in metas if m.get("action") == action], day, action))
        for m in metas:
            if m["meta_id"] not in picked:
                continue
            items.append({
                "date": day.isoformat(),
                "meta_id": m["meta_id"],
                "agent_id": m.get("agent_id"),
                "agent_name": m.get("agent_name"),
                "rule_group_primary": m.get("rule_group_primary"),
                "decision": m.get("decision"),
                "action": m.get("action"),
                "anomaly_score": m.get("anomaly_score"),
                "alert_count": m.get("alert_count"),
                "end_time": m.get("end_time"),
                "queue_reason": QUEUE_REASONS[m.get("action")],
                "verdict": verdicts.get(m["meta_id"]),
            })
    return items


def _ratio(num: int, den: int) -> Optional[float]:
    return num / den if den else None


def summarize_queue(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Ringkasan per hari: precision@ESCALATE dan temuan pada sampel SUPPRESS/DIGEST."""
    out: List[Dict[str, Any]] = []
    for day in sorted({i["date"] for i in items}):
        row: Dict[str, Any] = {"date": day}
        for reason, prefix in (("ESCALATE", "escalate"), ("SAMPLE_SUPPRESS", "suppress"), ("SAMPLE_DIGEST", "digest")):
            group = [i for i in items if i["date"] == day and i["queue_reason"] == reason]
            labeled = [i["verdict"]["verdict"] for i in group if i["verdict"]]
            row[f"{prefix}_in_queue"] = len(group)
            row[f"{prefix}_labeled"] = len(labeled)
            for v in VERDICTS:
                row[f"{prefix}_{v}"] = labeled.count(v)
        n = row["escalate_labeled"]
        row["precision_incident_at_escalate"] = _ratio(row["escalate_incident"], n)
        row["precision_actionable_at_escalate"] = _ratio(row["escalate_incident"] + row["escalate_actionable_benign"], n)
        out.append(row)
    return out
