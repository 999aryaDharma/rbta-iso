"""Unit test lifecycle thread LiveWorker."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import List, Optional
import threading
import time

import pytest

from src.contracts.raw_alert import CanonicalRawAlert
from src.runtime.durable_state import DurableStateManager
from src.runtime.live_coordinator import LiveCycleResult
from src.runtime.live_worker import LiveWorker
from src.runtime.service import LiveRBTAService


def make_alert(idx: int, ts: datetime) -> CanonicalRawAlert:
    return CanonicalRawAlert(
        wazuh_alert_id=f"live-w-{idx}",
        timestamp=ts,
        agent_id="001",
        agent_name="soc-1",
        rule_group_primary="pam",
        rule_level=3,
        rule_id="5501",
        mitre_tactics=(),
        srcip=None,
        agent_criticality=1,
    )


class ScriptedCoordinator:
    """Test double untuk LiveIngestionCoordinator dengan hasil siklus yang sudah ditentukan."""

    def __init__(self, service: LiveRBTAService, script: List[object]) -> None:
        self.service = service
        self._script = list(script)
        self.calls = 0

    def run_cycle(self, current_time: Optional[datetime] = None) -> LiveCycleResult:
        self.calls += 1
        outcome = self._script.pop(0) if self._script else "ok"
        if isinstance(outcome, BaseException):
            raise outcome
        return LiveCycleResult(
            fast_candidates=0,
            recent_reconciliation_candidates=0,
            full_reconciliation_candidates=0,
            submitted_candidates=0,
            duplicate_noops=0,
            processed_new_ids=0,
            failures=0,
            new_scored_meta_alerts=0,
        )


def make_service(tmp_path: Path, model_version: str = "live-test-v1") -> LiveRBTAService:
    pipeline = SimpleNamespace(metadata={"model_version": model_version})
    return LiveRBTAService(
        scoring_pipeline=pipeline,  # type: ignore[arg-type]
        state_manager=DurableStateManager(tmp_path / "state.json"),
    )


def wait_until(predicate, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def test_double_start_keeps_single_thread(tmp_path: Path):
    service = make_service(tmp_path)
    worker = LiveWorker(service, ScriptedCoordinator(service, []), poll_interval=0.01)
    try:
        assert worker.start() is True
        assert worker.start() is False
        assert worker.is_alive()
        assert threading.active_count() >= 2
    finally:
        worker.stop()


def test_stop_is_idempotent(tmp_path: Path):
    service = make_service(tmp_path)
    worker = LiveWorker(service, ScriptedCoordinator(service, []), poll_interval=0.01)
    worker.start()
    worker.stop()
    worker.stop()
    assert not worker.is_alive()


def test_cycle_failure_is_recorded_and_worker_survives(tmp_path: Path):
    service = make_service(tmp_path)
    coordinator = ScriptedCoordinator(service, [RuntimeError("indexer down"), "ok"])
    worker = LiveWorker(service, coordinator, poll_interval=0.01)
    try:
        worker.start()
        assert wait_until(lambda: coordinator.calls >= 2)
        assert worker.is_alive()
        status = worker.status()
        assert status["cycles_completed"] >= 1
        assert status["consecutive_failures"] == 0
        assert "indexer down" in (status["last_error"] or "")
    finally:
        worker.stop()


def test_model_version_pinned_in_source_state(tmp_path: Path):
    service = make_service(tmp_path, model_version="live-pin-v9")
    worker = LiveWorker(service, ScriptedCoordinator(service, []), poll_interval=0.01)
    try:
        worker.start()
        state = service.get_live_source_state()
        assert state.get("live_model_version") == "live-pin-v9"
    finally:
        worker.stop()


def test_stop_with_drain_finalizes_open_bucket(tmp_path: Path):
    from src.contracts.scored_meta_alert import ScoredMetaAlert

    service = make_service(tmp_path)
    now = datetime(2026, 9, 29, tzinfo=timezone.utc)
    service.ingest_alert(make_alert(1, now), auto_persist=False)

    def fake_score(meta):
        return ScoredMetaAlert(
            meta_id=meta.meta_id,
            agent_id=meta.agent_id,
            agent_name=meta.agent_name,
            rule_group_primary=meta.rule_group_primary,
            start_time=meta.start_time,
            end_time=meta.end_time,
            alert_count=meta.alert_count,
            max_severity=meta.max_severity,
            mitre_tactics=meta.mitre_tactics_unique,
            seven_features={},
            raw_model_score=0.0,
            anomaly_score=0.0,
            threshold_used=0.0,
            decision="NOISE",
            action="SUPPRESS",
            escalate=False,
            model_version="live-test-v1",
            feature_schema_version="1.0",
            score_calibration_version="minmax-v1",
            source_alert_ids=meta.wazuh_alert_ids,
        )

    service.scoring_pipeline = SimpleNamespace(
        metadata={"model_version": "live-test-v1"}, score_single=fake_score
    )
    worker = LiveWorker(
        service, ScriptedCoordinator(service, []), poll_interval=3600.0, drain_on_stop=True
    )
    worker.start()
    worker.stop()
    assert len(service.get_history()) == 1
    assert service.get_history()[0].source_alert_ids == ("live-w-1",)


def test_worker_disabled_by_default_without_env():
    from src.runtime.live_worker import worker_enabled_from_env

    assert worker_enabled_from_env({}) is False
    assert worker_enabled_from_env({"RBTA_LIVE_WORKER_ENABLED": "false"}) is False
    assert worker_enabled_from_env({"RBTA_LIVE_WORKER_ENABLED": "true"}) is True
    assert worker_enabled_from_env({"RBTA_LIVE_WORKER_ENABLED": " True "}) is True


# Drain default False (hanya untuk decommission).

def test_drain_defaults_to_false():
    from src.runtime.live_worker import drain_on_stop_from_env

    assert drain_on_stop_from_env({}) is False
    assert drain_on_stop_from_env({"RBTA_LIVE_WORKER_DRAIN_ON_STOP": "false"}) is False
    assert drain_on_stop_from_env({"RBTA_LIVE_WORKER_DRAIN_ON_STOP": "true"}) is True


def test_live_worker_constructor_drain_defaults_to_false(tmp_path: Path):
    service = make_service(tmp_path)
    worker = LiveWorker(service, ScriptedCoordinator(service, []))
    assert worker.drain_on_stop is False


def test_stop_without_drain_preserves_open_bucket(tmp_path: Path):
    service = make_service(tmp_path)
    now = datetime(2026, 9, 29, tzinfo=timezone.utc)
    service.ingest_alert(make_alert(1, now), auto_persist=False)
    worker = LiveWorker(service, ScriptedCoordinator(service, []), poll_interval=3600.0)
    worker.start()
    worker.stop()
    assert len(service.get_history()) == 0


def _install_fake_scoring(service: LiveRBTAService) -> None:
    from src.contracts.scored_meta_alert import ScoredMetaAlert

    def fake_score(meta):
        return ScoredMetaAlert(
            meta_id=meta.meta_id,
            agent_id=meta.agent_id,
            agent_name=meta.agent_name,
            rule_group_primary=meta.rule_group_primary,
            start_time=meta.start_time,
            end_time=meta.end_time,
            alert_count=meta.alert_count,
            max_severity=meta.max_severity,
            mitre_tactics=meta.mitre_tactics_unique,
            seven_features={},
            raw_model_score=0.0,
            anomaly_score=0.0,
            threshold_used=0.0,
            decision="NOISE",
            action="SUPPRESS",
            escalate=False,
            model_version="live-test-v1",
            feature_schema_version="1.0",
            score_calibration_version="minmax-v1",
            source_alert_ids=meta.wazuh_alert_ids,
        )

    service.scoring_pipeline = SimpleNamespace(
        metadata={"model_version": "live-test-v1"}, score_single=fake_score
    )


def test_restart_without_drain_matches_uninterrupted_run(tmp_path: Path):
    """Kesetaraan: ingest, stop (tanpa drain), restart pada state yang sama, lalu drain
    decommission eksplisit harus sama dengan drain tanpa interupsi.
    """
    now = datetime(2026, 9, 29, tzinfo=timezone.utc)

    state_a = tmp_path / "a" / "state.json"
    svc_a = LiveRBTAService(
        scoring_pipeline=SimpleNamespace(metadata={"model_version": "live-test-v1"}),
        state_manager=DurableStateManager(state_a),
    )
    _install_fake_scoring(svc_a)
    svc_a.ingest_alert(make_alert(1, now), auto_persist=False)
    w1 = LiveWorker(svc_a, ScriptedCoordinator(svc_a, []), poll_interval=3600.0)
    w1.start()
    w1.stop()
    assert len(svc_a.get_history()) == 0

    svc_a2 = LiveRBTAService(
        scoring_pipeline=svc_a.scoring_pipeline,
        state_manager=DurableStateManager(state_a),
    )
    w2 = LiveWorker(svc_a2, ScriptedCoordinator(svc_a2, []), poll_interval=3600.0,
                    drain_on_stop=True)
    w2.start()
    w2.stop()
    assert len(svc_a2.get_history()) == 1

    state_b = tmp_path / "b" / "state.json"
    svc_b = LiveRBTAService(
        scoring_pipeline=SimpleNamespace(metadata={"model_version": "live-test-v1"}),
        state_manager=DurableStateManager(state_b),
    )
    _install_fake_scoring(svc_b)
    svc_b.ingest_alert(make_alert(1, now), auto_persist=False)
    ref = svc_b.drain_and_score()
    assert len(ref) == 1

    restarted = svc_a2.get_history()[0]
    assert restarted.meta_id == ref[0].meta_id
    assert restarted.source_alert_ids == ref[0].source_alert_ids
    assert (restarted.agent_id, restarted.rule_group_primary) == (
        ref[0].agent_id, ref[0].rule_group_primary)


# Penjaga pin model.

def test_pin_mismatch_rejects_start(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("RBTA_LIVE_MODEL_OVERRIDE", raising=False)
    service = make_service(tmp_path, model_version="v-old")
    w = LiveWorker(service, ScriptedCoordinator(service, []), poll_interval=3600.0)
    try:
        w.start()
    finally:
        w.stop()
    service.scoring_pipeline = SimpleNamespace(metadata={"model_version": "v-new"})
    w2 = LiveWorker(service, ScriptedCoordinator(service, []), poll_interval=3600.0)
    with pytest.raises(RuntimeError, match="mismatch"):
        w2.start()
    assert not w2.is_alive()


def test_pin_override_allows_mismatch(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("RBTA_LIVE_MODEL_OVERRIDE", "v-new")
    service = make_service(tmp_path, model_version="v-old")
    w = LiveWorker(service, ScriptedCoordinator(service, []), poll_interval=3600.0)
    try:
        w.start()
    finally:
        w.stop()
    service.scoring_pipeline = SimpleNamespace(metadata={"model_version": "v-new"})
    w2 = LiveWorker(service, ScriptedCoordinator(service, []), poll_interval=3600.0)
    try:
        assert w2.start() is True
        assert service.get_live_source_state().get("live_model_version") == "v-new"
    finally:
        w2.stop()


def test_pin_new_run_id_allows_mismatch(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("RBTA_LIVE_MODEL_OVERRIDE", raising=False)
    service = make_service(tmp_path, model_version="v-old")
    service.run_id = "run-old"
    w = LiveWorker(service, ScriptedCoordinator(service, []), poll_interval=3600.0)
    try:
        w.start()
    finally:
        w.stop()
    service.scoring_pipeline = SimpleNamespace(metadata={"model_version": "v-new"})
    service.run_id = "run-new"
    w2 = LiveWorker(service, ScriptedCoordinator(service, []), poll_interval=3600.0)
    try:
        assert w2.start() is True
    finally:
        w2.stop()


def test_pin_missing_metadata_raises(tmp_path: Path):
    service = make_service(tmp_path, model_version="whatever")
    service.scoring_pipeline = SimpleNamespace(metadata={})
    worker = LiveWorker(service, ScriptedCoordinator(service, []), poll_interval=3600.0)
    with pytest.raises(RuntimeError, match="model_version"):
        worker.start()
    assert not worker.is_alive()


# Exponential backoff + jitter lewat sleep_fn yang bisa di-inject.

def test_backoff_second_delay_exceeds_first(tmp_path: Path):
    delays = []
    holder = {}

    def fake_sleep(seconds: float) -> None:
        delays.append(seconds)
        if len(delays) >= 3:
            holder["worker"]._stop_event.set()

    service = make_service(tmp_path)
    coordinator = ScriptedCoordinator(
        service, [RuntimeError("boom-1"), RuntimeError("boom-2"), "ok"])
    worker = LiveWorker(service, coordinator, poll_interval=0.05, sleep_fn=fake_sleep)
    holder["worker"] = worker
    worker._run()
    assert len(delays) >= 2, f"expected >=2 backoff sleeps, got {delays}"
    assert delays[1] > delays[0], f"backoff must grow: {delays}"
    assert worker.consecutive_failures == 0


# Lock file OS.

def test_acquire_state_lock_second_holder_rejected(tmp_path: Path):
    from src.runtime.live_worker import acquire_state_lock, release_state_lock

    target = tmp_path / "state.json"
    try:
        acquire_state_lock(target)
        with pytest.raises(RuntimeError, match="another live writer holds"):
            acquire_state_lock(target)
    finally:
        release_state_lock(target)


# Penjaga hash derivasi (antarmuka lintas komponen, dijaga getattr).

def test_derivation_mismatch_rejects_start(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("RBTA_LIVE_DERIVATION_OVERRIDE", raising=False)
    service = make_service(tmp_path)
    service.state_manager.get_derivation_hash = lambda: "hash-a"
    service.state_manager.compute_derivation_hash = lambda: "hash-b"
    worker = LiveWorker(service, ScriptedCoordinator(service, []), poll_interval=3600.0)
    with pytest.raises(RuntimeError, match="[Dd]erivation"):
        worker.start()
    assert not worker.is_alive()


def test_derivation_override_allows_mismatch(tmp_path: Path, monkeypatch):
    from src.runtime.durable_state import compute_derivation_hash

    monkeypatch.setenv("RBTA_LIVE_DERIVATION_OVERRIDE", compute_derivation_hash())
    service = make_service(tmp_path)
    service.state_manager.get_derivation_hash = lambda: "hash-a"
    service.state_manager.compute_derivation_hash = lambda: "hash-b"
    worker = LiveWorker(service, ScriptedCoordinator(service, []), poll_interval=3600.0)
    try:
        assert worker.start() is True
    finally:
        worker.stop()


def test_stop_skips_drain_when_thread_stuck(tmp_path: Path, monkeypatch, caplog):
    import logging

    import src.runtime.live_worker as live_worker_mod

    monkeypatch.setattr(live_worker_mod, "_JOIN_TIMEOUT_SEC", 0.2)
    release = threading.Event()
    entered = threading.Event()

    class StuckCoordinator:
        def run_cycle(self, current_time=None):
            entered.set()
            assert release.wait(10)

    service = make_service(tmp_path)
    now = datetime(2026, 9, 29, tzinfo=timezone.utc)
    service.ingest_alert(make_alert(1, now), auto_persist=False)
    worker = LiveWorker(service, StuckCoordinator(), poll_interval=0.01,
                        drain_on_stop=True)
    worker.start()
    assert entered.wait(5)
    with caplog.at_level(logging.WARNING):
        worker.stop()
    try:
        assert len(service.get_history()) == 0
        assert any("skipping drain" in rec.message for rec in caplog.records)
    finally:
        release.set()


def test_derivation_drift_refuses_start_and_fresh_start_pins(tmp_path: Path):
    """Penjaga aktif: hash tersimpan yang basi ditolak, start baru menyimpan baseline."""
    from src.runtime.durable_state import compute_derivation_hash

    service = make_service(tmp_path)
    service.state_manager.set_derivation_hash("stale-hash")
    worker = LiveWorker(service, ScriptedCoordinator(service, []), poll_interval=0.01)
    with pytest.raises(RuntimeError, match="derivation config mismatch"):
        worker.start()

    service2 = make_service(tmp_path / "fresh")
    worker2 = LiveWorker(service2, ScriptedCoordinator(service2, []), poll_interval=0.01)
    try:
        assert worker2.start() is True
        assert service2.state_manager.get_derivation_hash() == compute_derivation_hash()
    finally:
        worker2.stop()


# Lepas dan ambil ulang lock.

def test_acquire_release_reacquire_ok(tmp_path: Path):
    from src.runtime.live_worker import acquire_state_lock, release_state_lock

    target = tmp_path / "state.json"
    try:
        acquire_state_lock(target)
        with pytest.raises(RuntimeError, match="another live writer holds"):
            acquire_state_lock(target)
        release_state_lock(target)
        acquire_state_lock(target)
    finally:
        release_state_lock(target)


# Override harus sama dengan versi/hash target, bukan "true".

def test_pin_override_true_value_rejected(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("RBTA_LIVE_MODEL_OVERRIDE", "true")
    service = make_service(tmp_path, model_version="v-old")
    w = LiveWorker(service, ScriptedCoordinator(service, []), poll_interval=3600.0)
    try:
        w.start()
    finally:
        w.stop()
    service.scoring_pipeline = SimpleNamespace(metadata={"model_version": "v-new"})
    w2 = LiveWorker(service, ScriptedCoordinator(service, []), poll_interval=3600.0)
    with pytest.raises(RuntimeError, match="mismatch"):
        w2.start()
    assert not w2.is_alive()


def test_pin_override_exact_version_allowed_and_recorded(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("RBTA_LIVE_MODEL_OVERRIDE", "v-new")
    service = make_service(tmp_path, model_version="v-old")
    w = LiveWorker(service, ScriptedCoordinator(service, []), poll_interval=3600.0)
    try:
        w.start()
    finally:
        w.stop()
    service.scoring_pipeline = SimpleNamespace(metadata={"model_version": "v-new"})
    w2 = LiveWorker(service, ScriptedCoordinator(service, []), poll_interval=3600.0)
    try:
        assert w2.start() is True
        assert service.get_live_source_state().get("live_model_version") == "v-new"
    finally:
        w2.stop()


def test_derivation_override_true_value_rejected(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("RBTA_LIVE_DERIVATION_OVERRIDE", "true")
    service = make_service(tmp_path)
    service.state_manager.set_derivation_hash("stale-hash")
    worker = LiveWorker(service, ScriptedCoordinator(service, []), poll_interval=3600.0)
    with pytest.raises(RuntimeError, match="[Dd]erivation"):
        worker.start()
    assert not worker.is_alive()


def test_derivation_override_exact_hash_allowed(tmp_path: Path, monkeypatch):
    from src.runtime.durable_state import compute_derivation_hash

    monkeypatch.setenv("RBTA_LIVE_DERIVATION_OVERRIDE", compute_derivation_hash())
    service = make_service(tmp_path)
    service.state_manager.set_derivation_hash("stale-hash")
    worker = LiveWorker(service, ScriptedCoordinator(service, []), poll_interval=3600.0)
    try:
        assert worker.start() is True
    finally:
        worker.stop()


# Override eksplisit lewat constructor (env_map diteruskan server).

def test_constructor_explicit_model_override_without_env(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("RBTA_LIVE_MODEL_OVERRIDE", raising=False)
    service = make_service(tmp_path, model_version="v-old")
    w = LiveWorker(service, ScriptedCoordinator(service, []), poll_interval=3600.0)
    try:
        w.start()
    finally:
        w.stop()
    service.scoring_pipeline = SimpleNamespace(metadata={"model_version": "v-new"})
    w2 = LiveWorker(
        service, ScriptedCoordinator(service, []),
        poll_interval=3600.0, model_override="v-new",
    )
    try:
        assert w2.start() is True
    finally:
        w2.stop()


def test_constructor_explicit_derivation_override_without_env(tmp_path: Path, monkeypatch):
    from src.runtime.durable_state import compute_derivation_hash

    monkeypatch.delenv("RBTA_LIVE_DERIVATION_OVERRIDE", raising=False)
    service = make_service(tmp_path)
    service.state_manager.set_derivation_hash("stale-hash")
    worker = LiveWorker(
        service, ScriptedCoordinator(service, []),
        poll_interval=3600.0,
        derivation_override=compute_derivation_hash(),
    )
    try:
        assert worker.start() is True
    finally:
        worker.stop()


# Riwayat pin.

def test_pin_history_appends_new_versions_capped_at_20(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("RBTA_LIVE_MODEL_OVERRIDE", "v-new")
    service = make_service(tmp_path, model_version="v-old")
    w = LiveWorker(service, ScriptedCoordinator(service, []), poll_interval=3600.0)
    try:
        w.start()
    finally:
        w.stop()
    history = service.get_live_source_state().get("live_pin_history")
    assert isinstance(history, list) and len(history) == 1
    assert history[0]["version"] == "v-old" and "at" in history[0]

    service.scoring_pipeline = SimpleNamespace(metadata={"model_version": "v-new"})
    w2 = LiveWorker(service, ScriptedCoordinator(service, []), poll_interval=3600.0)
    try:
        assert w2.start() is True
    finally:
        w2.stop()
    history = service.get_live_source_state().get("live_pin_history")
    assert [e["version"] for e in history] == ["v-old", "v-new"]

    # Isi sampai batas: entri tertua dibuang, yang terbaru dipertahankan.
    service3 = make_service(tmp_path / "capped", model_version="v-cap")
    service3.update_live_source_state({
        "live_pin_history": [{"version": f"v-{i}", "at": "t"} for i in range(20)],
    })
    w3 = LiveWorker(service3, ScriptedCoordinator(service3, []), poll_interval=3600.0)
    try:
        assert w3.start() is True
    finally:
        w3.stop()
    history = service3.get_live_source_state().get("live_pin_history")
    assert len(history) == 20
    assert history[-1]["version"] == "v-cap"
    assert history[0]["version"] == "v-1"


# _sleep default menunggu di stop event.

def test_sleep_default_uses_stop_event(tmp_path: Path):
    service = make_service(tmp_path)
    worker = LiveWorker(service, ScriptedCoordinator(service, []))
    assert worker._sleep_fn is None
    worker._stop_event.set()
    started = time.monotonic()
    worker._sleep(60.0)
    assert time.monotonic() - started < 5.0


# live_first_started_at di-pin tepat sekali.

def test_first_started_at_written_once_across_restarts(tmp_path: Path):
    service = make_service(tmp_path)
    worker = LiveWorker(service, ScriptedCoordinator(service, []), poll_interval=3600.0)
    try:
        assert worker.start() is True
        first = service.get_live_source_state().get("live_first_started_at")
        assert first, "first start must record live_first_started_at"
        assert service.get_live_source_state().get("live_worker_started_at") == first
    finally:
        worker.stop()
    try:
        assert worker.start() is True
        second = service.get_live_source_state()
        assert second.get("live_first_started_at") == first
        assert second.get("live_worker_started_at"), "restart must refresh live_worker_started_at"
    finally:
        worker.stop()


# Override derivasi yang diterima mem-pin ulang baseline + dicatat di audit.

def test_derivation_override_repins_baseline_and_restart_without_override_ok(
    tmp_path: Path, monkeypatch
):
    from src.runtime.durable_state import compute_derivation_hash

    current = compute_derivation_hash()
    monkeypatch.setenv("RBTA_LIVE_DERIVATION_OVERRIDE", current)
    service = make_service(tmp_path)
    service.state_manager.set_derivation_hash("stale-hash")
    worker = LiveWorker(service, ScriptedCoordinator(service, []), poll_interval=3600.0)
    try:
        assert worker.start() is True
    finally:
        worker.stop()
    assert service.state_manager.get_derivation_hash() == current
    history = service.get_live_source_state().get("live_pin_history")
    assert isinstance(history, list)
    assert any(
        e.get("kind") == "derivation" and e.get("value") == current for e in history
    ), f"expected derivation re-pin audit in history, got {history}"
    # Restart TANPA override sekarang berhasil: baseline sudah di-pin ulang.
    monkeypatch.delenv("RBTA_LIVE_DERIVATION_OVERRIDE", raising=False)
    worker2 = LiveWorker(service, ScriptedCoordinator(service, []), poll_interval=3600.0)
    try:
        assert worker2.start() is True
    finally:
        worker2.stop()


def test_derivation_repin_history_capped_at_20(tmp_path: Path, monkeypatch):
    from src.runtime.durable_state import compute_derivation_hash

    current = compute_derivation_hash()
    monkeypatch.setenv("RBTA_LIVE_DERIVATION_OVERRIDE", current)
    service = make_service(tmp_path)
    service.state_manager.set_derivation_hash("stale-hash")
    service.update_live_source_state({
        "live_pin_history": [{"version": f"v-{i}", "at": "t"} for i in range(20)],
    })
    worker = LiveWorker(service, ScriptedCoordinator(service, []), poll_interval=3600.0)
    try:
        assert worker.start() is True
    finally:
        worker.stop()
    history = service.get_live_source_state().get("live_pin_history")
    assert len(history) == 20
    assert history[-1].get("kind") == "derivation"
    assert history[-1].get("value") == current


# Override model yang diterima mem-pin ulang + dicatat di audit; restart bersih.

def test_model_override_repin_audited_and_restart_without_override_ok(
    tmp_path: Path, monkeypatch
):
    monkeypatch.setenv("RBTA_LIVE_MODEL_OVERRIDE", "v-new")
    service = make_service(tmp_path, model_version="v-old")
    w = LiveWorker(service, ScriptedCoordinator(service, []), poll_interval=3600.0)
    try:
        w.start()
    finally:
        w.stop()
    service.scoring_pipeline = SimpleNamespace(metadata={"model_version": "v-new"})
    w2 = LiveWorker(service, ScriptedCoordinator(service, []), poll_interval=3600.0)
    try:
        assert w2.start() is True
        state = service.get_live_source_state()
        assert state.get("live_model_version") == "v-new"
        assert any(
            e.get("version") == "v-new" for e in (state.get("live_pin_history") or [])
        )
    finally:
        w2.stop()
    monkeypatch.delenv("RBTA_LIVE_MODEL_OVERRIDE", raising=False)
    w3 = LiveWorker(service, ScriptedCoordinator(service, []), poll_interval=3600.0)
    try:
        assert w3.start() is True
    finally:
        w3.stop()
