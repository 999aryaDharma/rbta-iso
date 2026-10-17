"""Integration test: kesetaraan mode batch dan replay."""
from datetime import datetime, timedelta, timezone
import random
import pytest

from src.contracts.raw_alert import CanonicalRawAlert
from src.contracts.scored_meta_alert import ScoredMetaAlert
from src.model.scoring_pipeline import ScoringPipeline, train_reference_pipeline
from src.runners.batch_runner import BatchResearchRunner
from src.runners.clock import ReplayClock
from src.runners.replay_runner import ReplayStreamRunner


def generate_equivalence_stream() -> list[CanonicalRawAlert]:
    """Bangkitkan aliran sintetis deterministik multi-agent dengan jitter out-of-order."""
    rng = random.Random(42)
    base_t = datetime(2026, 8, 28, 8, 0, 0, tzinfo=timezone.utc)
    stream: list[CanonicalRawAlert] = []

    # Agent 001: 120 event.
    curr_t = base_t
    for i in range(120):
        step = rng.choice([2, 5, 12, 18, 30])
        curr_t += timedelta(seconds=step)
        stream.append(
            CanonicalRawAlert(
                wazuh_alert_id=f"a001_{i:04d}",
                timestamp=curr_t,
                agent_id="001",
                agent_name="soc-1",
                rule_group_primary=rng.choice(["pam", "syslog", "web"]),
                rule_level=rng.randint(2, 12),
                rule_id=str(5500 + rng.randint(1, 10)),
                mitre_tactics=("Initial Access", "Execution") if i % 6 == 0 else (),
                srcip="192.168.1.10",
                agent_criticality=1,
            )
        )

    # Agent 002: 80 event.
    curr_t2 = base_t + timedelta(minutes=5)
    for i in range(80):
        curr_t2 += timedelta(seconds=rng.choice([1, 4, 8]))
        stream.append(
            CanonicalRawAlert(
                wazuh_alert_id=f"a002_{i:04d}",
                timestamp=curr_t2,
                agent_id="002",
                agent_name="db-prod",
                rule_group_primary="sql_injection" if i % 8 == 0 else "syslog",
                rule_level=rng.randint(3, 14),
                rule_id=str(6000 + rng.randint(1, 5)),
                mitre_tactics=("Defense Evasion",) if i % 4 == 0 else (),
                srcip="10.0.0.50",
                agent_criticality=4,
            )
        )

    # Acak untuk menyimulasikan kedatangan jaringan out-of-order yang terbatas.
    shuffled = list(stream)
    rng.shuffle(shuffled)
    return shuffled


def test_batch_and_replay_exact_equivalence():
    """BatchResearchRunner dan ReplayStreamRunner menghasilkan output yang identik 100%."""
    stream = generate_equivalence_stream()
    base_delta_t = timedelta(minutes=15)

    # Latih bundle artefak model dari output batch runner.
    unscored_batch = BatchResearchRunner(base_delta_t=base_delta_t, adaptive=True).run(stream)
    assert len(unscored_batch.meta_alerts) > 0

    bundle = train_reference_pipeline(
        unscored_batch.meta_alerts,
        random_state=42,
        model_version="equivalence-model-v1",
    )
    scoring_pipeline = ScoringPipeline(bundle)

    # Jalankan mode batch dengan scoring.
    batch_runner = BatchResearchRunner(
        base_delta_t=base_delta_t,
        adaptive=True,
        scoring_pipeline=scoring_pipeline,
    )
    batch_result = batch_runner.run(stream)
    batch_scored = batch_result.scored_meta_alerts
    assert batch_scored is not None

    # Jalankan mode replay (kecepatan MAX) dengan scoring pipeline dan aliran input yang sama.
    replay_runner = ReplayStreamRunner(
        scoring_pipeline=scoring_pipeline,
        clock=ReplayClock(speed_factor="MAX"),
        base_delta_t=base_delta_t,
        adaptive=True,
    )
    replay_scored = list(replay_runner.run(stream))

    # Kesetaraan ketat 100%.
    assert len(batch_scored) == len(replay_scored), (
        f"Count mismatch: batch produced {len(batch_scored)} vs replay {len(replay_scored)}"
    )

    for i, (b, r) in enumerate(zip(batch_scored, replay_scored)):
        assert b.meta_id == r.meta_id, f"Item {i}: meta_id {b.meta_id} != {r.meta_id}"
        assert b.agent_id == r.agent_id, f"Item {i}: agent_id {b.agent_id} != {r.agent_id}"
        assert b.rule_group_primary == r.rule_group_primary
        assert b.alert_count == r.alert_count
        assert b.max_severity == r.max_severity
        assert b.start_time == r.start_time
        assert b.end_time == r.end_time
        assert b.mitre_tactics == r.mitre_tactics
        assert b.source_alert_ids == r.source_alert_ids
        assert b.seven_features == r.seven_features
        assert b.raw_model_score == pytest.approx(r.raw_model_score, rel=1e-9)
        assert b.anomaly_score == pytest.approx(r.anomaly_score, rel=1e-9)
        assert b.threshold_used == pytest.approx(r.threshold_used, rel=1e-9)
        assert b.decision == r.decision
        assert b.action == r.action
        assert b.escalate == r.escalate
        assert b.model_version == r.model_version
