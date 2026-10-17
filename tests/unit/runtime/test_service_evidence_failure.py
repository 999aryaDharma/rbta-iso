from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType
import pytest

from src.contracts.raw_alert import CanonicalRawAlert
from src.model.scoring_pipeline import ScoringPipeline, train_reference_pipeline
from src.runners.batch_runner import BatchResearchRunner
from src.rbta.engine import RBTAEngine
from src.runtime.durable_state import DurableStateManager
from src.runtime.raw_evidence import RawAlertEvidenceStore, RawEvidenceConflictError
from src.runtime.service import LiveRBTAService


def make_alert(alert_id: str, rule_level: int = 5) -> CanonicalRawAlert:
    return CanonicalRawAlert(
        wazuh_alert_id=alert_id,
        timestamp=datetime(2026, 8, 29, 12, 0, 0, tzinfo=timezone.utc),
        agent_id="001",
        agent_name="agent-ubuntu",
        rule_group_primary="authentication_failed",
        rule_level=rule_level,
        rule_id="5710",
        mitre_tactics=("credential-access",),
        srcip="192.168.1.100",
        agent_criticality=1.0,
        metadata=MappingProxyType({}),
    )


def test_evidence_conflict_prevents_core_rbta_mutation(tmp_path: Path):
    db_path = tmp_path / "evidence.sqlite3"
    state_path = tmp_path / "state.json"

    # Latih bundle reference untuk pipeline.
    base_t = datetime(2026, 8, 29, 10, 0, 0, tzinfo=timezone.utc)
    sample_alerts = [
        make_alert(f"init-{i}", rule_level=(i % 12) + 1)
        for i in range(25)
    ]
    for i, a in enumerate(sample_alerts):
        object.__setattr__(a, 'timestamp', base_t + timedelta(hours=i))
    batch_res = BatchResearchRunner(base_delta_t=timedelta(minutes=15), adaptive=False).run(sample_alerts)
    bundle = train_reference_pipeline(batch_res.meta_alerts, random_state=42, model_version="test-v1")

    store = RawAlertEvidenceStore(db_path)
    state_manager = DurableStateManager(state_path)
    scoring_pipeline = ScoringPipeline(bundle)

    service = LiveRBTAService(
        scoring_pipeline=scoring_pipeline,
        state_manager=state_manager,
        raw_evidence_store=store,
    )

    alert1 = make_alert("aid-100", rule_level=5)
    service.ingest_alert(alert1)

    seen_before = set(service.engine._seen_alert_ids)
    assert "aid-100" in seen_before
    meta_counter_before = service.engine._meta_id_counter

    # Alert bertentangan: ID sama tetapi level berbeda.
    conflicting_alert = make_alert("aid-100", rule_level=15)

    with pytest.raises(RawEvidenceConflictError):
        service.ingest_alert(conflicting_alert)

    # State engine inti harus tidak berubah sama sekali.
    assert set(service.engine._seen_alert_ids) == seen_before
    assert service.engine._meta_id_counter == meta_counter_before
