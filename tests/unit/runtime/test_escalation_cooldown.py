"""T10: cooldown eskalasi berulang hanya kebijakan pengiriman Telegram."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3

from src.runtime.durable_state import DurableStateManager
from src.runtime.telegram_dispatcher import TelegramDispatcher
from tests.unit.runtime.test_telegram_dispatcher import _scored

T0 = datetime(2026, 10, 17, 2, 0, tzinfo=timezone.utc)


class _Service:
    def __init__(self, items, state_manager):
        self.outbox = list(items)
        self.state_manager = state_manager

    def get_outbox(self):
        return list(self.outbox)

    def commit_outbox(self, ids):
        before = len(self.outbox)
        self.outbox = [s for s in self.outbox if s.meta_id not in ids]
        return before - len(self.outbox)

    def get_live_source_state(self):
        return {"live_first_started_at": (T0 - timedelta(days=1)).isoformat()}


def test_repeated_escalation_is_suppressed_then_summarized(tmp_path: Path):
    now = [T0]
    manager = DurableStateManager(tmp_path / "state.json")
    items = [_scored(meta_id=i, end_time=T0) for i in (1, 2, 3)]
    other_group = _scored(meta_id=4, end_time=T0)
    object.__setattr__(other_group, "rule_group_primary", "web")
    service = _Service(items + [other_group], manager)
    sent = []
    d = TelegramDispatcher(service, sender=sent.append, bot_token="t", chat_id="c", dry_run=False,
                           min_interval_sec=0, cooldown_min=60, clock_fn=lambda: now[0])

    result = d.dispatch_once()
    assert result.sent == 2  # #1 dan #4 (kunci berbeda)
    assert result.suppressed_cooldown == 2  # #2, #3 dalam cooldown
    assert service.outbox == []  # tetap di-commit: tidak menumpuk di outbox
    with sqlite3.connect(manager.history_db_path) as conn:
        assert conn.execute("SELECT meta_id, reason FROM suppressed_notifications ORDER BY meta_id").fetchall() == [
            (2, "cooldown"), (3, "cooldown"),
        ]
    # Keputusan/aksi di data tidak berubah.
    assert all(s.action == "ESCALATE" and s.decision == "CRITICAL" for s in items)

    now[0] = T0 + timedelta(minutes=30)
    assert d.dispatch_once().cooldown_summaries == 0  # cooldown belum berakhir

    now[0] = T0 + timedelta(minutes=61)
    assert d.dispatch_once().cooldown_summaries == 1
    assert "+2 meta-alert serupa" in sent[-1]["message"] and "#2, #3" in sent[-1]["message"]
    assert len(sent) == 3
    assert d.dispatch_once().cooldown_summaries == 0  # ringkasan hanya sekali

    # Setelah cooldown berakhir, eskalasi berikutnya terkirim lagi.
    service.outbox = [_scored(meta_id=5, end_time=T0)]
    assert d.dispatch_once().sent == 1
    assert d.status()["suppressed_cooldown_total"] == 2


def test_zero_disables_cooldown(tmp_path: Path):
    manager = DurableStateManager(tmp_path / "state.json")
    service = _Service([_scored(meta_id=i, end_time=T0) for i in (1, 2)], manager)
    sent = []
    d = TelegramDispatcher(service, sender=sent.append, bot_token="t", chat_id="c", dry_run=False,
                           min_interval_sec=0, cooldown_min=0)
    assert d.dispatch_once().sent == 2


def test_default_cooldown_is_sixty_minutes(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("RBTA_ESCALATION_COOLDOWN_MIN", raising=False)
    d = TelegramDispatcher(_Service([], DurableStateManager(tmp_path / "s.json")), bot_token="t", chat_id="c")
    assert d.status()["cooldown_min"] == 60.0
