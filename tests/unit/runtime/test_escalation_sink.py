"""Unit test EscalationSink dan DeferredTelegramFileSink."""

from datetime import datetime, timezone
import json
from pathlib import Path
import pytest

from src.contracts.scored_meta_alert import ScoredMetaAlert
from src.runtime.escalation_sink import DeferredTelegramFileSink


def _create_mock_scored_meta(
    meta_id: int = 1,
    decision: str = "CRITICAL",
    action: str = "ESCALATE",
    anomaly_score: float = 0.4215,
    threshold: float = 0.4028,
) -> ScoredMetaAlert:
    return ScoredMetaAlert(
        meta_id=meta_id,
        agent_id="001",
        agent_name="prod-wazuh-agent",
        rule_group_primary="authentication_failed",
        start_time=datetime(2026, 8, 29, 10, 0, 0, tzinfo=timezone.utc),
        end_time=datetime(2026, 8, 29, 10, 5, 0, tzinfo=timezone.utc),
        alert_count=12,
        max_severity=9,
        mitre_tactics=("initial-access", "credential-access"),
        seven_features={
            "max_severity": 9.0,
            "mitre_tactic_count": 2.0,
            "critical_mitre_tactic_present": 1.0,
            "alert_count_log": 2.4849,
            "rule_diversity_shannon": 0.85,
            "severity_dispersion": 0.72,
            "agent_criticality": 2.0,
        },
        raw_model_score=0.1523,
        anomaly_score=anomaly_score,
        threshold_used=threshold,
        decision=decision,
        action=action,
        escalate=(action == "ESCALATE"),
        model_version="rbta-if-v1",
        feature_schema_version="1.0",
        score_calibration_version="minmax-v1",
        source_alert_ids=("alert-001", "alert-002"),
        metadata={},
    )


def test_deferred_telegram_sink_escalate_emits(tmp_path: Path):
    sink_file = tmp_path / "telegram_escalate_payloads.txt"
    sink = DeferredTelegramFileSink(sink_file)

    scored = _create_mock_scored_meta(meta_id=101, action="ESCALATE", decision="CRITICAL")
    result = sink.emit(scored, run_id="run-alpha")

    assert result is True
    assert sink.get_total_count() == 1
    assert sink_file.exists()

    payloads = sink.get_latest_payloads(10)
    assert len(payloads) == 1
    p = payloads[0]
    assert p["meta_id"] == 101
    assert p["run_id"] == "run-alpha"
    assert p["idempotency_key"] == "run-alpha:101"
    assert p["decision"] == "CRITICAL"
    assert p["action"] == "ESCALATE"
    assert p["anomaly_score"] == round(0.4215, 6)
    assert p["threshold"] == round(0.4028, 6)
    assert p["agent_id"] == "001"
    assert p["rule_group_primary"] == "authentication_failed"
    assert p["alert_count"] == 12
    assert p["max_severity"] == 9
    assert "authentication_failed" in p["message"]
    assert p["parse_mode"] == "HTML"
    assert "Run:</b> <code>run-alpha</code>" in p["message"]


def test_deferred_telegram_sink_ignores_non_escalate(tmp_path: Path):
    sink_file = tmp_path / "telegram_escalate_payloads.txt"
    sink = DeferredTelegramFileSink(sink_file)

    scored_suppress = _create_mock_scored_meta(meta_id=102, action="SUPPRESS", decision="NOISE")
    scored_digest = _create_mock_scored_meta(meta_id=103, action="DAILY_DIGEST", decision="CONTEXTUAL_ANOMALY")

    assert sink.emit(scored_suppress, run_id="run-alpha") is False
    assert sink.emit(scored_digest, run_id="run-alpha") is False
    assert sink.get_total_count() == 0
    assert not sink_file.exists()


def test_deferred_telegram_sink_idempotency(tmp_path: Path):
    sink_file = tmp_path / "telegram_escalate_payloads.txt"
    sink = DeferredTelegramFileSink(sink_file)

    scored = _create_mock_scored_meta(meta_id=104, action="ESCALATE")
    
    # Emit pertama berhasil.
    assert sink.emit(scored, run_id="run-alpha") is True
    # Emit duplikat dalam run yang sama ditolak.
    assert sink.emit(scored, run_id="run-alpha") is False
    assert sink.get_total_count() == 1

    # meta_id sama di run_id berbeda berhasil.
    assert sink.emit(scored, run_id="run-beta") is True
    assert sink.get_total_count() == 2

    lines = [line.strip() for line in sink_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 2


def test_deferred_telegram_sink_reload_preserves_keys(tmp_path: Path):
    sink_file = tmp_path / "telegram_escalate_payloads.txt"
    sink1 = DeferredTelegramFileSink(sink_file)

    scored1 = _create_mock_scored_meta(meta_id=201, action="ESCALATE")
    sink1.emit(scored1, run_id="run-1")

    # Instance kedua yang menunjuk ke file yang sama.
    sink2 = DeferredTelegramFileSink(sink_file)
    assert sink2.get_total_count() == 1
    
    # Emit ulang scored1 ke sink2 harus di-dedup.
    assert sink2.emit(scored1, run_id="run-1") is False

    scored2 = _create_mock_scored_meta(meta_id=202, action="ESCALATE")
    assert sink2.emit(scored2, run_id="run-1") is True
    assert sink2.get_total_count() == 2
