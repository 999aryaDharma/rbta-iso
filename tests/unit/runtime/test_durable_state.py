"""Unit test DurableStateManager dan pemulihan state setelah crash."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import sqlite3
import pytest

from src.contracts.raw_alert import CanonicalRawAlert
from src.rbta.engine import RBTAEngine
from src.runtime.durable_state import DurableStateManager


def make_alert(idx: int, ts: datetime, agent_id: str = "001", group: str = "pam") -> CanonicalRawAlert:
    return CanonicalRawAlert(
        wazuh_alert_id=f"alert_{idx}",
        timestamp=ts,
        agent_id=agent_id,
        agent_name=f"soc-{agent_id}",
        rule_group_primary=group,
        rule_level=3,
        rule_id="5501",
        mitre_tactics=(),
        srcip=None,
        agent_criticality=1,
    )


def test_durable_state_save_and_restore_engine(tmp_path: Path):
    """State engine (ID seen, state temporal, bucket aktif, counter) tersimpan ke disk dan pulih secara identik."""
    state_file = tmp_path / "runtime_state.json"
    manager = DurableStateManager(state_file)

    engine = RBTAEngine(base_delta_t=timedelta(minutes=15))
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)

    # Ingest 2 alert ke bucket aktif.
    a1 = make_alert(1, base_t, agent_id="001", group="pam")
    a2 = make_alert(2, base_t + timedelta(minutes=5), agent_id="001", group="pam")
    engine.process(a1)
    engine.process(a2)

    # Ingest 1 alert ke bucket agent lain.
    b1 = make_alert(3, base_t + timedelta(minutes=2), agent_id="002", group="syslog")
    engine.process(b1)

    # Simpan state.
    manager.save_state(
        engine=engine,
        outbox=[{"item": 1, "meta_id": 100}],
        source_checkpoint={"mode": "live", "offset": 42},
    )
    assert state_file.exists()

    # Buat engine kosong baru dan pulihkan state dari disk.
    restored_engine = RBTAEngine(base_delta_t=timedelta(minutes=15))
    restored_data = manager.restore_state(restored_engine)

    assert restored_data["source_checkpoint"] == {"mode": "live", "offset": 42}
    assert restored_data["outbox"] == [{"item": 1, "meta_id": 100}]

    # Struktur internal engine harus pulih.
    assert restored_engine._seen_alert_ids == {"alert_1", "alert_2", "alert_3"}
    assert ("001", "pam") in restored_engine._active_buckets
    assert ("002", "syslog") in restored_engine._active_buckets

    bucket_001 = restored_engine._active_buckets[("001", "pam")]
    assert bucket_001.alert_count == 2
    assert bucket_001.wazuh_alert_ids == ["alert_1", "alert_2"]
    assert bucket_001.end_time == base_t + timedelta(minutes=5)
    assert restored_engine.snapshot_agents()[0]["agent_name"] == "soc-001"

    # Memproses alert_1 duplikat di engine hasil pemulihan bersifat idempoten.
    assert restored_engine.process(a1) == []
    assert restored_engine._active_buckets[("001", "pam")].alert_count == 2

    # Memproses alert_4 baru di engine hasil pemulihan ter-merge ke bucket yang sudah dipulihkan.
    a4 = make_alert(4, base_t + timedelta(minutes=10), agent_id="001", group="pam")
    assert restored_engine.process(a4) == []
    assert restored_engine._active_buckets[("001", "pam")].alert_count == 3
    assert restored_engine._active_buckets[("001", "pam")].wazuh_alert_ids == ["alert_1", "alert_2", "alert_4"]


def test_seen_alert_ids_are_persisted_in_sqlite_not_rewritten_in_json(tmp_path: Path):
    """JSON checkpoint tetap terbatas ukurannya sementara proteksi duplikat bertahan setelah restart."""
    state_file = tmp_path / "runtime_state.json"
    manager = DurableStateManager(state_file)
    engine = RBTAEngine(base_delta_t=timedelta(minutes=15))
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)

    for idx in range(25):
        engine.process(make_alert(idx, base_t + timedelta(seconds=idx)))
    manager.save_state(engine=engine)

    payload = json.loads(state_file.read_text(encoding="utf-8"))
    assert "seen_alert_ids" not in payload
    assert manager.count_seen_alert_ids() == 25

    restored = RBTAEngine(base_delta_t=timedelta(minutes=15))
    manager.restore_state(restored)
    assert restored._seen_alert_ids == {f"alert_{idx}" for idx in range(25)}


def test_finalized_history_supports_indexed_pagination_and_direct_lookup(tmp_path: Path):
    manager = DurableStateManager(tmp_path / "state.json")
    manager.append_finalized([
        {"meta_id": idx, "decision": "CRITICAL" if idx % 2 else "NOISE", "agent_id": "001", "agent_name": "soc", "rule_group_primary": "pam", "anomaly_score": idx / 10}
        for idx in range(1, 11)
    ])

    items, total = manager.query_finalized(page=2, page_size=2, decision="CRITICAL", sort_by="meta_id", sort_order="desc")
    assert total == 5
    assert [item["meta_id"] for item in items] == [5, 3]
    assert manager.get_finalized(8)["meta_id"] == 8
    assert manager.get_finalized(999) is None


def test_restore_only_loads_bounded_recent_history(tmp_path: Path):
    manager = DurableStateManager(tmp_path / "state.json")
    manager.append_finalized([{"meta_id": idx} for idx in range(1, 1202)])
    restored = manager.restore_state(RBTAEngine(base_delta_t=timedelta(minutes=15)))
    assert len(restored["finalized_history"]) == 1000
    assert restored["finalized_history"][0]["meta_id"] == 202


def test_failed_checkpoint_does_not_commit_seen_ids_or_history(tmp_path):
    manager = DurableStateManager(tmp_path / "state.json")
    engine = RBTAEngine()
    now = datetime(2026, 9, 28, tzinfo=timezone.utc)
    engine.process(make_alert(1, now))
    manager.save_state(engine)
    engine.process(make_alert(2, now + timedelta(seconds=1)))

    with pytest.raises(TypeError):
        manager.save_state(
            engine, source_checkpoint={"invalid": object()},
            new_finalized_history=[{"meta_id": 42}],
        )

    restored = RBTAEngine()
    manager.restore_state(restored)
    assert not manager.has_seen_alert_id("alert_2")
    assert manager.get_finalized(42) is None
    assert restored._active_buckets[("001", "pam")].wazuh_alert_ids == ["alert_1"]
    assert "alert_2" in engine._new_seen_alert_ids


def test_recovery_after_json_publication_failure_keeps_dedup_and_bucket_together(tmp_path, monkeypatch):
    manager = DurableStateManager(tmp_path / "state.json")
    engine = RBTAEngine()
    now = datetime(2026, 9, 28, tzinfo=timezone.utc)
    engine.process(make_alert(1, now))
    manager.save_state(engine)
    engine.process(make_alert(2, now + timedelta(seconds=1)))

    def fail_replace(*args, **kwargs):
        raise OSError("simulated interrupted JSON publication")

    monkeypatch.setattr(Path, "replace", fail_replace)
    try:
        manager.save_state(engine)
    except OSError:
        pass
    restored = RBTAEngine()
    DurableStateManager(manager.state_path).restore_state(restored)
    assert restored._seen_alert_ids == set(restored._active_buckets[("001", "pam")].wazuh_alert_ids)
    assert restored._active_buckets[("001", "pam")].wazuh_alert_ids == ["alert_1", "alert_2"]


def test_sqlite_checkpoint_failure_rolls_back_history_dedup_and_snapshot(tmp_path):
    manager = DurableStateManager(tmp_path / "state.json")
    engine = RBTAEngine()
    now = datetime(2026, 9, 28, tzinfo=timezone.utc)
    engine.process(make_alert(1, now))
    manager.save_state(engine, source_checkpoint={"cursor": 1})
    engine.process(make_alert(2, now + timedelta(seconds=1)))
    with sqlite3.connect(manager.history_db_path) as conn:
        conn.execute("CREATE TRIGGER fail_checkpoint BEFORE INSERT ON runtime_snapshot BEGIN SELECT RAISE(ABORT, 'disk failure'); END")
    with pytest.raises(sqlite3.IntegrityError, match="disk failure"):
        manager.save_state(engine, source_checkpoint={"cursor": 2}, new_finalized_history=[{"meta_id": 42}])
    recovered = RBTAEngine()
    restored = manager.restore_state(recovered)
    assert restored["source_checkpoint"] == {"cursor": 1}
    assert not manager.has_seen_alert_id("alert_2")
    assert manager.get_finalized(42) is None
    assert recovered._active_buckets[("001", "pam")].alert_count == 1
    assert "alert_2" in engine._new_seen_alert_ids


def test_legacy_json_snapshot_migrates_without_reset(tmp_path):
    state = tmp_path / "state.json"
    state.write_text(json.dumps({
        "schema_version": "1.0", "seen_alert_ids": ["legacy-alert"],
        "meta_id_counter": 7, "source_checkpoint": {"cursor": "legacy"},
        "pending_scoring": [], "outbox": [{"meta_id": 6}],
    }), encoding="utf-8")
    manager = DurableStateManager(state)
    engine = RBTAEngine()
    restored = manager.restore_state(engine)
    manager.save_state(engine, outbox=restored["outbox"], source_checkpoint=restored["source_checkpoint"])
    state.unlink()  # setelah migrasi, SQLite saja harus cukup
    recovered = RBTAEngine()
    restored = DurableStateManager(state).restore_state(recovered)
    assert recovered._seen_alert_ids == {"legacy-alert"}
    assert recovered._meta_id_counter == 7
    assert restored["outbox"] == [{"meta_id": 6}]
    assert restored["source_checkpoint"] == {"cursor": "legacy"}


def test_restore_recreates_parent_dir_removed_between_init_and_restore(tmp_path):
    import gc
    import shutil

    state = tmp_path / "nested" / "state.json"
    manager = DurableStateManager(state)
    del manager
    gc.collect()
    shutil.rmtree(tmp_path / "nested")
    manager = DurableStateManager(state)
    restored = manager.restore_state(RBTAEngine())
    assert restored["outbox"] == []
    assert restored["source_checkpoint"] == {}
    assert state.parent.exists()


def test_derivation_hash_roundtrip_and_stable(tmp_path: Path):
    """Hash derivasi stabil antar pemanggilan dan utuh saat disimpan-dibaca lewat manager."""
    from src.runtime.durable_state import compute_derivation_hash

    h1 = compute_derivation_hash()
    h2 = compute_derivation_hash()
    assert h1 == h2
    assert len(h1) == 64
    int(h1, 16)  # hex sha256 huruf kecil yang valid

    manager = DurableStateManager(tmp_path / "state.json")
    assert manager.get_derivation_hash() is None
    manager.set_derivation_hash(h1)
    assert manager.get_derivation_hash() == h1


def test_evidence_cache_overflow_flushes_before_clear(tmp_path: Path):
    """Cache dedup yang penuh mem-flush evidence yang masih di buffer ke SQLite sebelum dikosongkan,
    sehingga duplikat bertentangan dari alert yang belum di-flush tetap terdeteksi.
    """
    from src.runtime.raw_evidence import RawAlertEvidenceStore, RawEvidenceConflictError

    store = RawAlertEvidenceStore(db_path=tmp_path / "ev.sqlite3", batch_size=1000)
    store._max_recent_fingerprints = 2
    base = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)

    store.store(make_alert(1, base))
    store.store(make_alert(2, base))
    store.store(make_alert(3, base))  # melebihi cache -> harus flush dulu, baru dikosongkan

    conflicting = CanonicalRawAlert(
        wazuh_alert_id="alert_1",
        timestamp=base,
        agent_id="001",
        agent_name="soc-001",
        rule_group_primary="pam",
        rule_level=9,
        rule_id="5509",
        mitre_tactics=(),
        srcip=None,
        agent_criticality=4,
    )
    with pytest.raises(RawEvidenceConflictError):
        store.store(conflicting)
    assert store.get("alert_1") is not None


def test_empty_stored_fingerprint_raises_integrity_error(tmp_path: Path):
    """Baris tersimpan dengan fingerprint kanonis kosong adalah korupsi, bukan konflik."""
    import sqlite3

    from src.runtime.raw_evidence import RawAlertEvidenceStore, RawEvidenceIntegrityError

    store = RawAlertEvidenceStore(db_path=tmp_path / "ev.sqlite3")
    base = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    with sqlite3.connect(store.db_path) as conn:
        conn.execute(
            "INSERT INTO raw_alert_evidence (wazuh_alert_id, canonical_fingerprint, fingerprint_version,"
            " timestamp, agent_id, agent_name, rule_id, rule_level, rule_group_primary,"
            " agent_criticality, ingested_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            ("alert_9", "", 2, base.isoformat(), "001", "soc-001", "5501", 3, "pam", 1.0, base.isoformat()),
        )
        conn.commit()

    with pytest.raises(RawEvidenceIntegrityError, match="empty.*fingerprint|fingerprint.*empty"):
        store.store(make_alert(9, base))


def test_first_save_backs_up_non_12_mirror_once(tmp_path: Path):
    """Penyimpanan pertama yang menimpa mirror JSON non-1.2 menyalinnya ke .pre-1.2.bak tepat sekali."""
    legacy = {
        "schema_version": "1.0",
        "seen_alert_ids": [],
        "meta_id_counter": 1,
        "source_checkpoint": {},
        "outbox": [],
    }
    state = tmp_path / "state.json"
    state.write_text(json.dumps(legacy), encoding="utf-8")

    manager = DurableStateManager(state)
    engine = RBTAEngine()
    manager.save_state(engine)

    bak = tmp_path / "state.json.pre-1.2.bak"
    assert bak.exists()
    assert json.loads(bak.read_text(encoding="utf-8")) == legacy
    assert json.loads(state.read_text(encoding="utf-8"))["schema_version"] == "1.2"

    frozen_bak = bak.read_text(encoding="utf-8")
    manager.save_state(engine)
    assert bak.read_text(encoding="utf-8") == frozen_bak


def test_quarantine_add_returns_count_first_then_repeat(tmp_path: Path):
    """quarantine_add mengembalikan count per ID (1 pada pelanggaran pertama, 2 pada pengulangan)."""
    manager = DurableStateManager(tmp_path / "state.json")
    assert manager.quarantine_add("alert_1", error_type="E1") == 1
    assert manager.quarantine_add("alert_1", error_type="E1") == 2
    assert manager.quarantine_count() == 1


def test_quarantine_add_many_single_flush_returns_counts(tmp_path: Path):
    """Quarantine batch dalam satu panggilan; count dikembalikan per entri sesuai urutan."""
    manager = DurableStateManager(tmp_path / "state.json")
    entries = [
        {"wazuh_alert_id": "a1", "source_index": "idx", "source_document_id": "d1", "error_type": "E1"},
        {"wazuh_alert_id": "a2", "source_index": "idx", "source_document_id": "d2", "error_type": "E2"},
    ]
    assert manager.quarantine_add_many(entries) == [1, 1]
    assert manager.quarantine_add_many(entries) == [2, 2]
    assert manager.quarantine_count() == 2
    assert manager.quarantine_add_many([]) == []


def test_quarantine_release_and_count(tmp_path: Path):
    """Release menghapus berdasarkan ID dan mengembalikan jumlah baris terdampak; count = COUNT(*)."""
    manager = DurableStateManager(tmp_path / "state.json")
    manager.quarantine_add("a1", error_type="E1")
    manager.quarantine_add("a2", error_type="E2")
    assert manager.quarantine_count() == 2
    assert manager.quarantine_release("a1") == 1
    assert manager.quarantine_release("a1") == 0
    assert manager.quarantine_release("unknown-id") == 0
    assert manager.quarantine_count() == 1


def test_suppression_add_and_count(tmp_path: Path):
    """API untuk dispatcher: tambah/hitung meta ID yang notifikasinya ditahan."""
    manager = DurableStateManager(tmp_path / "state.json")
    assert manager.suppression_count() == 0
    manager.suppression_add(7, "daily digest")
    manager.suppression_add(9, "suppressed noise")
    assert manager.suppression_count() == 2
    manager.suppression_add(7, "daily digest")  # penahanan ulang bersifat idempoten
    assert manager.suppression_count() == 2


def test_derivation_hash_fail_closed_on_unreadable_config(tmp_path: Path, monkeypatch):
    """Tidak ada fallback 'v1' diam-diam — konfigurasi yang tidak bisa dibaca harus error."""
    from src.runtime import durable_state as ds

    monkeypatch.setattr("src.config.domain.AGENT_CRITICALITY", None)
    with pytest.raises(Exception):
        ds.compute_derivation_hash()


def test_derivation_hash_pins_canonicalizer_version(tmp_path: Path):
    """CANONICALIZER_VERSION termasuk dalam dict derivasi yang di-hash."""
    import hashlib
    import json as _json

    from src.config import domain as _domain
    from src.runtime import durable_state as ds

    assert ds.CANONICALIZER_VERSION == "1.0"
    derivation = {
        "agent_criticality": dict(sorted(_domain.AGENT_CRITICALITY.items())),
        "group_severity_weight": dict(sorted(_domain.GROUP_SEVERITY_WEIGHT.items())),
        "critical_mitre_tactics": sorted(str(t) for t in _domain.CRITICAL_MITRE_TACTICS),
        "default_agent_criticality": _domain.DEFAULT_AGENT_CRITICALITY,
        "default_rule_group_weight": _domain.DEFAULT_RULE_GROUP_WEIGHT,
        "canonicalizer_version": ds.CANONICALIZER_VERSION,
    }
    expected = hashlib.sha256(
        _json.dumps(derivation, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    assert ds.compute_derivation_hash() == expected


def test_derivation_hash_covers_all_canonicalizer_tables(tmp_path: Path, monkeypatch):
    """Setiap tabel domain yang dibaca resolve_primary_rule_group / get_agent_criticality
    mengubah hash (tidak ada yang luput diam-diam).
    """
    from src.runtime import durable_state as ds

    base = ds.compute_derivation_hash()
    cases = [
        ("AGENT_CRITICALITY", {**__import__("src.config.domain", fromlist=["AGENT_CRITICALITY"]).AGENT_CRITICALITY, "probe-agent": 4}),
        ("GROUP_SEVERITY_WEIGHT", {"probe-group": 10}),
        ("CRITICAL_MITRE_TACTICS", frozenset({"Probe Tactic"})),
        ("DEFAULT_AGENT_CRITICALITY", 4),
        ("DEFAULT_RULE_GROUP_WEIGHT", 10),
    ]
    for attr, value in cases:
        monkeypatch.setattr(f"src.config.domain.{attr}", value)
        assert ds.compute_derivation_hash() != base, f"hash blind to {attr}"
        monkeypatch.undo()


def test_save_state_meta_id_collision_fails_closed(tmp_path: Path):
    """meta_id batch yang bertabrakan dengan finalized_history melempar error; state yang sudah di-commit tetap utuh."""
    manager = DurableStateManager(tmp_path / "state.json")
    manager.append_finalized([{"meta_id": 42, "marker": "original"}])
    engine = RBTAEngine()
    now = datetime(2026, 9, 28, tzinfo=timezone.utc)
    engine.process(make_alert(1, now))

    with pytest.raises(RuntimeError, match="42"):
        manager.save_state(engine, new_finalized_history=[{"meta_id": 42, "marker": "clobber"}])

    assert manager.get_finalized(42)["marker"] == "original"
    assert not manager.has_seen_alert_id("alert_1")
    recovered = RBTAEngine()
    restored = manager.restore_state(recovered)
    assert restored["source_checkpoint"] == {}
    assert "alert_1" in engine._new_seen_alert_ids


def test_restore_history_only_sets_counter_to_max_plus_one(tmp_path: Path):
    """Restore yang hanya berisi history (tanpa snapshot) melanjutkan counter di MAX(meta_id)+1."""
    manager = DurableStateManager(tmp_path / "state.json")
    manager.append_finalized([{"meta_id": 5}, {"meta_id": 9}, {"meta_id": 7}])
    engine = RBTAEngine()
    manager.restore_state(engine)
    assert engine._meta_id_counter == 10


def test_restore_history_only_empty_keeps_counter_at_one(tmp_path: Path):
    """Batas: history kosong membiarkan counter engine baru di 1."""
    manager = DurableStateManager(tmp_path / "state.json")
    engine = RBTAEngine()
    manager.restore_state(engine)
    assert engine._meta_id_counter == 1


def test_restore_without_snapshot_but_with_seen_ids_fails_closed(tmp_path: Path):
    """Snapshot SQLite yang hilang dengan ID seen yang tidak kosong harus error, tidak pernah mengisi dedup ke engine kosong."""
    manager = DurableStateManager(tmp_path / "state.json")
    engine = RBTAEngine()
    now = datetime(2026, 9, 28, tzinfo=timezone.utc)
    engine.process(make_alert(1, now))
    manager.save_state(engine)
    assert manager.count_seen_alert_ids() == 1

    with sqlite3.connect(manager.history_db_path) as conn:
        conn.execute("DELETE FROM runtime_snapshot")
        conn.commit()
    manager.filepath.unlink()  # mirror JSON juga dihapus: hanya dedup SQLite yang tersisa

    with pytest.raises((ValueError, RuntimeError), match="snapshot"):
        manager.restore_state(RBTAEngine())


def test_finalized_collision_identical_data_is_idempotent(tmp_path: Path):
    """Checkpoint ulang dengan data skor yang identik byte-per-byte adalah no-op yang aman,
    bukan tabrakan (checkpoint yang di-retry bisa berhasil tanpa kehilangan data).
    """
    manager = DurableStateManager(tmp_path / "state.json")
    engine = RBTAEngine()
    now = datetime(2026, 9, 28, tzinfo=timezone.utc)
    engine.process(make_alert(1, now))
    batch = [{"meta_id": 42, "marker": "same"}]
    manager.save_state(engine, new_finalized_history=batch)
    manager.save_state(engine, new_finalized_history=[dict(batch[0])])  # tidak boleh error
    assert manager.get_finalized(42) == {"meta_id": 42, "marker": "same"}


def test_finalized_collision_differing_data_still_fails_closed(tmp_path: Path):
    """Batas: isi identik lolos, tetapi baris berbeda di bawah meta_id yang sudah di-commit
    tetap error dan data aslinya dipertahankan.
    """
    manager = DurableStateManager(tmp_path / "state.json")
    engine = RBTAEngine()
    now = datetime(2026, 9, 28, tzinfo=timezone.utc)
    engine.process(make_alert(1, now))
    manager.save_state(engine, new_finalized_history=[{"meta_id": 42, "marker": "original"}])
    with pytest.raises(RuntimeError, match="42"):
        manager.save_state(engine, new_finalized_history=[{"meta_id": 42, "marker": "clobber"}])
    assert manager.get_finalized(42) == {"meta_id": 42, "marker": "original"}


def test_quarantine_id_set_returns_id_only_set(tmp_path: Path):
    """quarantine_id_set hanya mengembalikan set ID (filter skip yang murah, tanpa kolom tampilan)."""
    manager = DurableStateManager(tmp_path / "state.json")
    assert manager.quarantine_id_set() == set()
    manager.quarantine_add("a1", error_type="E1")
    manager.quarantine_add("a2", error_type="E2")
    assert manager.quarantine_id_set() == {"a1", "a2"}


def test_notification_add_and_count(tmp_path: Path):
    """Tabel notification_log + API notification_add/count untuk dispatcher."""
    manager = DurableStateManager(tmp_path / "state.json")
    assert manager.notification_count() == 0
    row_id1 = manager.notification_add(7, "run-1", "ESCALATE")
    row_id2 = manager.notification_add(9, "run-1", "SUPPRESS")
    assert isinstance(row_id1, int) and isinstance(row_id2, int)
    assert row_id2 == row_id1 + 1  # INTEGER PK AUTOINCREMENT
    assert manager.notification_count() == 2
    with sqlite3.connect(manager.history_db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, meta_id, run_id, verdict, at FROM notification_log ORDER BY id"
        ).fetchall()
    assert [dict(r) for r in rows] == [
        {"id": row_id1, "meta_id": 7, "run_id": "run-1", "verdict": "ESCALATE", "at": rows[0]["at"]},
        {"id": row_id2, "meta_id": 9, "run_id": "run-1", "verdict": "SUPPRESS", "at": rows[1]["at"]},
    ]
    assert all(r["at"] for r in rows)
