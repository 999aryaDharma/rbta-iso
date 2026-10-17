"""Unit test ReplayStreamRunner."""
from datetime import datetime, timedelta, timezone
import pytest

from src.contracts.raw_alert import CanonicalRawAlert
from src.contracts.scored_meta_alert import ScoredMetaAlert
from src.model.scoring_pipeline import ScoringPipeline, train_reference_pipeline
from src.runners.batch_runner import BatchResearchRunner
from src.runners.clock import ReplayClock
from src.runners.replay_runner import ReplayStreamRunner


def make_alert(idx: int, ts: datetime, group: str = "pam", level: int = 3, agent_idx: int = 1, mitre: tuple[str, ...] = ()) -> CanonicalRawAlert:
    return CanonicalRawAlert(
        wazuh_alert_id=f"alert_{idx}",
        timestamp=ts,
        agent_id=f"agent_{agent_idx}",
        agent_name=f"soc-{agent_idx}",
        rule_group_primary=group,
        rule_level=level,
        rule_id=f"550{idx % 5}",
        mitre_tactics=mitre,
        srcip=None,
        agent_criticality=agent_idx,
    )


def test_replay_runner_streams_and_scores_event_by_event():
    """Replay runner memproses aliran masuk, memajukan clock, dan yield ScoredMetaAlert."""
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    alerts = [
        make_alert(
            i,
            base_t + timedelta(minutes=i * 20),
            level=(i % 12) + 1,
            agent_idx=(i % 4) + 1,
            mitre=("Execution",) if i % 3 == 0 else (),
        )
        for i in range(30)
    ]

    # Siapkan model.
    batch_res = BatchResearchRunner(base_delta_t=timedelta(minutes=15), adaptive=False).run(alerts)
    bundle = train_reference_pipeline(batch_res.meta_alerts, random_state=42, model_version="replay-v1")
    scoring_pipe = ScoringPipeline(bundle)

    clock = ReplayClock(speed_factor="MAX")
    replay_runner = ReplayStreamRunner(
        scoring_pipeline=scoring_pipe,
        clock=clock,
        base_delta_t=timedelta(minutes=15),
        adaptive=False,
    )

    scored_stream = list(replay_runner.run(alerts))
    assert len(scored_stream) == 30
    assert all(isinstance(s, ScoredMetaAlert) for s in scored_stream)
