"""Unit test kontrak DTO ScoredMetaAlert."""
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
import pytest
from src.contracts.scored_meta_alert import ScoredMetaAlert


def test_scored_meta_alert_valid_instantiation():
    """Instansiasi ScoredMetaAlert yang valid."""
    t1 = datetime(2026, 8, 28, 5, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 8, 28, 5, 15, 0, tzinfo=timezone.utc)

    features = {
        "max_severity": 7.0,
        "mitre_tactic_count": 2.0,
        "critical_mitre_tactic_present": 1.0,
        "alert_count_log": 1.7918,
        "rule_diversity_shannon": 0.6931,
        "severity_dispersion": 1.5,
        "agent_criticality": 3.0,
    }

    scored = ScoredMetaAlert(
        meta_id=1,
        agent_id="002",
        agent_name="pusatkarir",
        rule_group_primary="authentication_failed",
        start_time=t1,
        end_time=t2,
        alert_count=5,
        max_severity=7,
        mitre_tactics=("Credential Access", "Defense Evasion"),
        seven_features=features,
        raw_model_score=0.45,
        anomaly_score=0.82,
        threshold_used=0.75,
        decision="CRITICAL",
        action="ESCALATE",
        escalate=True,
        model_version="rbta-if-20260828-v1",
        feature_schema_version="1.0",
        score_calibration_version="minmax-v1",
        source_alert_ids=("id1", "id2", "id3", "id4", "id5"),
        metadata={"run_id": "run-001"},
    )
    assert scored.meta_id == 1
    assert scored.decision == "CRITICAL"
    assert scored.action == "ESCALATE"
    assert scored.escalate is True
    assert scored.model_version == "rbta-if-20260828-v1"
    assert len(scored.seven_features) == 7
    assert len(scored.source_alert_ids) == 5


def test_scored_meta_alert_immutability():
    """Atribut ScoredMetaAlert tidak bisa diubah setelah dibuat."""
    t1 = datetime(2026, 8, 28, 5, 0, 0, tzinfo=timezone.utc)
    features = {
        "max_severity": 3.0,
        "mitre_tactic_count": 0.0,
        "critical_mitre_tactic_present": 0.0,
        "alert_count_log": 0.6931,
        "rule_diversity_shannon": 0.0,
        "severity_dispersion": 0.0,
        "agent_criticality": 1.0,
    }
    scored = ScoredMetaAlert(
        meta_id=1,
        agent_id="001",
        agent_name="soc-1",
        rule_group_primary="syslog",
        start_time=t1,
        end_time=t1,
        alert_count=1,
        max_severity=3,
        mitre_tactics=(),
        seven_features=features,
        raw_model_score=0.1,
        anomaly_score=0.2,
        threshold_used=0.75,
        decision="NOISE",
        action="SUPPRESS",
        escalate=False,
        model_version="v1",
        feature_schema_version="1.0",
        score_calibration_version="v1",
        source_alert_ids=("id1",),
    )
    with pytest.raises((FrozenInstanceError, AttributeError)):
        scored.decision = "CRITICAL"


def test_scored_meta_alert_nested_features_immutability():
    """Mapping seven_features dan metadata tidak bisa dimutasi in-place."""
    t1 = datetime(2026, 8, 28, 5, 0, 0, tzinfo=timezone.utc)
    features = {
        "max_severity": 3.0,
        "mitre_tactic_count": 0.0,
        "critical_mitre_tactic_present": 0.0,
        "alert_count_log": 0.6931,
        "rule_diversity_shannon": 0.0,
        "severity_dispersion": 0.0,
        "agent_criticality": 1.0,
    }
    scored = ScoredMetaAlert(
        meta_id=1,
        agent_id="001",
        agent_name="soc-1",
        rule_group_primary="syslog",
        start_time=t1,
        end_time=t1,
        alert_count=1,
        max_severity=3,
        mitre_tactics=(),
        seven_features=features,
        raw_model_score=0.1,
        anomaly_score=0.2,
        threshold_used=0.75,
        decision="NOISE",
        action="SUPPRESS",
        escalate=False,
        model_version="v1",
        feature_schema_version="1.0",
        score_calibration_version="v1",
        source_alert_ids=("id1",),
        metadata={"run_id": "run-001"},
    )
    with pytest.raises(TypeError):
        scored.seven_features["max_severity"] = 99.0

    with pytest.raises(TypeError):
        scored.metadata["run_id"] = "mutated-run"


def test_scored_meta_alert_invalid_decision_or_action():
    """Validasi nilai decision dan action."""
    t1 = datetime(2026, 8, 28, 5, 0, 0, tzinfo=timezone.utc)
    features = {
        "max_severity": 3.0,
        "mitre_tactic_count": 0.0,
        "critical_mitre_tactic_present": 0.0,
        "alert_count_log": 0.6931,
        "rule_diversity_shannon": 0.0,
        "severity_dispersion": 0.0,
        "agent_criticality": 1.0,
    }
    with pytest.raises(ValueError, match="decision"):
        ScoredMetaAlert(
            meta_id=1,
            agent_id="001",
            agent_name="soc-1",
            rule_group_primary="syslog",
            start_time=t1,
            end_time=t1,
            alert_count=1,
            max_severity=3,
            mitre_tactics=(),
            seven_features=features,
            raw_model_score=0.1,
            anomaly_score=0.2,
            threshold_used=0.75,
            decision="INVALID_DECISION",
            action="SUPPRESS",
            escalate=False,
            model_version="v1",
            feature_schema_version="1.0",
            score_calibration_version="v1",
            source_alert_ids=("id1",),
        )
