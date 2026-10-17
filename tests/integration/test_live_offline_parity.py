"""T3: paritas jalur offline (BatchResearchRunner) vs live (LiveRBTAService) dengan model thesis.

Varian 1 — urutan terurut: meta_id, anggota, alert_count, start/end, anomaly_score (1e-9),
decision, dan action harus identik.

Varian 2 — 5% alert dipindah maksimal 10 posisi (seed tetap). Perbedaan yang DIHARAPKAN:
* Offline memakai LosslessReorderBuffer (kapasitas 50) sehingga pergeseran <= 50 posisi
  dipulihkan penuh: hasilnya sama dengan varian terurut.
* Live (RBTA_ORDER_BUFFER_ENABLED=false, default deploy/ct) meneruskan alert apa adanya ke
  engine; alert terlambat ditangani kasus B (masuk window aktif) atau kasus C (memperlebar
  start bila jeda <= Δt, selain itu singleton). Jadi live boleh berbeda dari offline, tetapi
  harus identik dengan RBTAEngine murni pada urutan yang sama, dan tidak ada alert yang hilang.
  Terukur saat tes ditulis (2026-10-17): untuk fixture ini ke-40 grup anggota live tetap sama
  dengan offline (pergeseran <= 10 posisi selalu jatuh di dalam Δt, kasus B/C merge), tetapi
  hal itu sifat fixture, bukan jaminan; pergeseran yang melampaui Δt menghasilkan singleton.
"""

from datetime import datetime, timedelta
import json
from pathlib import Path
import random
from typing import Dict, List

import pytest

from src.config.research import MAX_BUCKET_DURATION
from src.contracts.raw_alert import CanonicalRawAlert
from src.model.scoring_pipeline import ScoringPipeline
from src.rbta.engine import RBTAEngine
from src.runners.batch_runner import BatchResearchRunner
from src.runtime.durable_state import DurableStateManager
from src.runtime.raw_evidence import RawAlertEvidenceStore
from src.runtime.service import LiveRBTAService
from tests.thesis_artifacts import require_thesis_model

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "live_offline_parity_alerts.jsonl"
# Δt run skripsi (phase_a_results.json: selected_delta_t_minutes = 10).
THESIS_DELTA_T = timedelta(minutes=10)


def load_fixture_alerts() -> List[CanonicalRawAlert]:
    alerts = []
    for line in FIXTURE.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        row["timestamp"] = datetime.fromisoformat(row["timestamp"])
        row["mitre_tactics"] = tuple(row["mitre_tactics"])
        alerts.append(CanonicalRawAlert(**row))
    return alerts


def run_offline(pipeline: ScoringPipeline, alerts: List[CanonicalRawAlert]):
    result = BatchResearchRunner(base_delta_t=THESIS_DELTA_T, adaptive=True, scoring_pipeline=pipeline).run(alerts)
    return sorted(result.scored_meta_alerts, key=lambda s: s.meta_id)


def run_live(pipeline: ScoringPipeline, alerts: List[CanonicalRawAlert], state_dir: Path):
    service = LiveRBTAService(
        scoring_pipeline=pipeline,
        state_manager=DurableStateManager(state_dir / "state.json"),
        base_delta_t=THESIS_DELTA_T,
        adaptive=True,
        raw_evidence_store=RawAlertEvidenceStore(state_dir / "evidence.sqlite3"),
        source_mode="LIVE",
    )
    scored = []
    for alert in alerts:
        scored.extend(service.ingest_alert(alert))
    scored.extend(service.drain_and_score())
    return sorted(scored, key=lambda s: s.meta_id)


def signature(scored) -> Dict[int, tuple]:
    return {
        s.meta_id: (
            s.agent_id, s.rule_group_primary, s.alert_count, s.start_time, s.end_time,
            tuple(sorted(s.source_alert_ids)), s.decision, s.action,
        )
        for s in scored
    }


def assert_conserving_and_homogeneous(scored, alerts: List[CanonicalRawAlert]) -> None:
    by_id = {a.wazuh_alert_id: a for a in alerts}
    members = [aid for s in scored for aid in s.source_alert_ids]
    assert sorted(members) == sorted(by_id), "alert hilang atau terduplikasi"
    for s in scored:
        group = [by_id[aid] for aid in s.source_alert_ids]
        assert {(a.agent_id, a.rule_group_primary) for a in group} == {(s.agent_id, s.rule_group_primary)}
        assert s.start_time == min(a.timestamp for a in group)
        assert s.end_time == max(a.timestamp for a in group)
        assert s.end_time - s.start_time <= MAX_BUCKET_DURATION
        assert s.alert_count == len(group)


@pytest.fixture(scope="module")
def pipeline() -> ScoringPipeline:
    return ScoringPipeline(require_thesis_model())


@pytest.fixture(scope="module")
def alerts() -> List[CanonicalRawAlert]:
    data = load_fixture_alerts()
    assert len(data) >= 300
    assert len({a.agent_id for a in data}) >= 3
    assert len({a.rule_group_primary for a in data}) >= 3
    assert any(a.mitre_tactics for a in data) and any(not a.mitre_tactics for a in data)
    return data


def test_sorted_stream_offline_and_live_are_identical(pipeline, alerts, tmp_path: Path):
    offline = run_offline(pipeline, alerts)
    live = run_live(pipeline, alerts, tmp_path)

    assert signature(live) == signature(offline)
    for o, l in zip(offline, live):
        assert l.raw_model_score == pytest.approx(o.raw_model_score, abs=1e-9)
        assert l.anomaly_score == pytest.approx(o.anomaly_score, abs=1e-9)
        assert l.threshold_used == o.threshold_used
    # Fixture memang menghasilkan beberapa kuadran Decision Matrix (bukan satu kelas saja).
    assert len({s.action for s in offline}) >= 2
    assert_conserving_and_homogeneous(live, alerts)


def shuffled_5_percent(alerts: List[CanonicalRawAlert], seed: int = 20261017, max_shift: int = 10):
    rng = random.Random(seed)
    order = list(alerts)
    for idx in rng.sample(range(len(order)), k=max(1, len(order) // 20)):
        item = order.pop(idx)
        order.insert(min(len(order), max(0, idx + rng.randint(-max_shift, max_shift))), item)
    assert order != list(alerts)
    return order


def test_reordered_stream_follows_engine_rules(pipeline, alerts, tmp_path: Path):
    reordered = shuffled_5_percent(alerts)
    baseline = signature(run_offline(pipeline, alerts))

    # Offline: reorder buffer memulihkan urutan, hasil sama dengan varian terurut.
    assert signature(run_offline(pipeline, reordered)) == baseline

    # Live: tidak ada alert hilang dan agregasi = RBTAEngine murni pada urutan yang sama (kasus B/C).
    live = run_live(pipeline, reordered, tmp_path)
    assert_conserving_and_homogeneous(live, alerts)

    engine = RBTAEngine(base_delta_t=THESIS_DELTA_T, adaptive=True)
    expected = [m for a in reordered for m in engine.process(a)] + engine.drain()
    assert {s.meta_id: tuple(s.source_alert_ids) for s in live} == {
        m.meta_id: tuple(m.wazuh_alert_ids) for m in expected
    }
    for s, meta in zip(live, sorted(expected, key=lambda m: m.meta_id)):
        assert s.anomaly_score == pytest.approx(pipeline.score_single(meta).anomaly_score, abs=1e-9)
