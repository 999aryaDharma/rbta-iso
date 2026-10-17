"""T7: finalized_at / sent_at dicatat aditif dan latensi event->finalize, finalize->sent dihitung."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3

from src.runtime.durable_state import DurableStateManager
from tests.unit.runtime.test_live_coordinator import create_test_service, make_raw_alert


def test_legacy_db_is_migrated_in_place(tmp_path: Path):
    db = tmp_path / "finalized_history.sqlite3"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE finalized_history (meta_id INTEGER PRIMARY KEY, scored_data TEXT NOT NULL,"
                     " inserted_at TEXT NOT NULL DEFAULT (datetime('now')))")
        conn.execute("INSERT INTO finalized_history (meta_id, scored_data) VALUES (1, '{\"meta_id\": 1}')")
        conn.execute("CREATE TABLE notification_log (id INTEGER PRIMARY KEY AUTOINCREMENT, meta_id INTEGER,"
                     " run_id TEXT, verdict TEXT, at TEXT NOT NULL DEFAULT (datetime('now')))")
    manager = DurableStateManager(tmp_path / "state.json")
    DurableStateManager(tmp_path / "state.json")  # migrasi idempoten
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT meta_id, finalized_at FROM finalized_history").fetchall() == [(1, None)]
        cols = {r[1] for r in conn.execute("PRAGMA table_info(notification_log)")}
    assert "sent_at" in cols
    assert manager.get_finalized(1) == {"meta_id": 1}


def test_finalized_and_sent_timestamps_produce_latency(tmp_path: Path):
    service = create_test_service(tmp_path)
    t0 = datetime.now(timezone.utc) - timedelta(minutes=50)
    service.ingest_alert(make_raw_alert(1, t0))
    # Alert kedua > Δt (15 mnt) kemudian -> bucket pertama final.
    scored = service.ingest_alert(make_raw_alert(2, t0 + timedelta(minutes=30)))
    assert len(scored) == 1
    meta_id = scored[0].meta_id
    service.state_manager.notification_add(meta_id, "live", "SENT")
    service.state_manager.notification_add(meta_id, "live", "DRY_RUN")

    db = service.state_manager.history_db_path
    with sqlite3.connect(db) as conn:
        finalized_at = conn.execute("SELECT finalized_at FROM finalized_history WHERE meta_id=?", (meta_id,)).fetchone()[0]
        sent = conn.execute("SELECT verdict, sent_at FROM notification_log ORDER BY id").fetchall()
    assert finalized_at is not None
    assert sent[0][1] is not None and sent[1][1] is None

    now = datetime.now(timezone.utc)
    samples = service.state_manager.latency_samples((now - timedelta(hours=1)).isoformat(), now.isoformat())
    # event->finalize = finalized_at - end_time (end_time = t0, alert tunggal) ~ 50 menit.
    assert samples["event_to_finalize"] == [(datetime.fromisoformat(finalized_at) - t0).total_seconds()]
    assert 0 <= samples["finalize_to_sent"][0] < 60
    summary = service.state_manager.latency_summary((now - timedelta(hours=1)).isoformat(), now.isoformat())
    assert summary["event_to_finalize_n"] == 1
    assert summary["event_to_finalize_p50"] == summary["event_to_finalize_p95"] == samples["event_to_finalize"][0]
    # Serialisasi scored_data tidak berubah (kolom aditif, bukan field JSON baru).
    assert "finalized_at" not in service.state_manager.get_finalized(meta_id)
