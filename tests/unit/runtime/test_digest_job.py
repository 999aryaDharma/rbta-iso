"""T9: daily digest NOISE_HIGH (pengelompokan, urutan, tidak terkirim ganda)."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3

from src.runtime.digest_job import build_digest_groups, format_digest, run_digest
from src.runtime.durable_state import DurableStateManager
from src.runtime.telegram_dispatcher import TelegramDispatcher

NOW = datetime(2026, 10, 16, 23, 30, tzinfo=timezone.utc)  # 17 Okt 07:30 WITA


def _insert(manager, rows):
    with sqlite3.connect(manager.history_db_path) as conn:
        for i, (agent, group, decision, count, sev, hours_ago) in enumerate(rows, 1):
            end = NOW - timedelta(hours=hours_ago)
            conn.execute("INSERT INTO finalized_history (meta_id, scored_data) VALUES (?, ?)", (i, json.dumps({
                "meta_id": i, "agent_id": "00" + str(len(agent)), "agent_name": agent, "rule_group_primary": group,
                "decision": decision, "action": "DAILY_DIGEST", "alert_count": count, "max_severity": sev,
                "start_time": (end - timedelta(minutes=5)).isoformat(), "end_time": end.isoformat(),
            })))


def _manager(tmp_path: Path):
    manager = DurableStateManager(tmp_path / "state.json")
    _insert(manager, [
        ("web-1", "web", "NOISE_HIGH", 3, 8, 1),
        ("web-1", "web", "NOISE_HIGH", 5, 10, 2),
        ("db-1", "syscheck", "NOISE_HIGH", 40, 7, 3),
        ("db-1", "pam", "NOISE_HIGH", 2, 7, 4),
        ("db-1", "pam", "NOISE_HIGH", 1, 9, 5),
        ("db-1", "pam", "NOISE_HIGH", 1, 7, 6),
        ("web-1", "web", "CRITICAL", 9, 12, 1),  # bukan NOISE_HIGH
        ("web-1", "web", "NOISE_HIGH", 9, 12, 30),  # di luar 24 jam
    ])
    return manager


class _Service:
    def get_outbox(self):
        return []

    def commit_outbox(self, ids):
        return 0


def test_groups_are_aggregated_and_ordered(tmp_path: Path):
    manager = _manager(tmp_path)
    groups = build_digest_groups(manager.history_db_path, (NOW - timedelta(hours=24)).isoformat(), NOW.isoformat())
    assert [(g["agent"], g["rule_group_primary"], g["meta_alerts"], g["total_alerts"], g["max_severity"]) for g in groups] == [
        ("db-1", "pam", 3, 4, 9),
        ("web-1", "web", 2, 8, 10),
        ("db-1", "syscheck", 1, 40, 7),
    ]
    assert groups[0]["first"] < groups[0]["last"]
    text = format_digest(groups, "2026-10-17", "http://ct:8010/dashboard/")
    assert text.index("db-1 · pam") < text.index("web-1 · web")
    assert "http://ct:8010/dashboard/meta-alerts?decision=NOISE_HIGH&amp;search=pam" in text


def test_limit_top_ten(tmp_path: Path):
    manager = DurableStateManager(tmp_path / "state.json")
    _insert(manager, [(f"a{i:02d}", "web", "NOISE_HIGH", 1, 7, 1) for i in range(15)])
    groups = build_digest_groups(manager.history_db_path, (NOW - timedelta(hours=24)).isoformat(), NOW.isoformat())
    assert len(groups) == 10 and groups[0]["agent"] == "a00"


def test_digest_sent_once_per_day(tmp_path: Path):
    manager = _manager(tmp_path)
    sent = []
    dispatcher = TelegramDispatcher(_Service(), sender=sent.append, bot_token="t", chat_id="c", dry_run=False,
                                    min_interval_sec=0)
    assert run_digest(manager, dispatcher, NOW) == "sent"
    assert run_digest(manager, dispatcher, NOW + timedelta(hours=1)) == "duplicate"
    assert len(sent) == 1 and "DAILY DIGEST" in sent[0]["message"]
    assert run_digest(manager, dispatcher, NOW + timedelta(days=1)) == "sent"
    assert len(sent) == 2


def test_digest_respects_dry_run_and_hold(tmp_path: Path):
    manager = _manager(tmp_path)
    dry = TelegramDispatcher(_Service(), sender=lambda p: (_ for _ in ()).throw(AssertionError("no send")),
                             bot_token="t", chat_id="c", dry_run=True)
    assert run_digest(manager, dry, NOW) == "dry_run"
    assert dry.dry_run_payloads[-1]["idempotency_key"].endswith("digest:2026-10-17")
    held = TelegramDispatcher(_Service(), bot_token="", chat_id="", dry_run=False)
    other = DurableStateManager(tmp_path / "b" / "state.json")
    assert run_digest(other, held, NOW) == "held"
    assert run_digest(other, held, NOW) == "held"  # held tidak dicatat, bisa dicoba lagi
