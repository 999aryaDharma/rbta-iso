"""Unit test Decision Matrix dan False Positive Gate."""
import pytest
from src.model.decision import evaluate_decision


def test_decision_matrix_four_quadrants():
    """Empat kuadran decision matrix standar saat False Positive Gate tidak aktif."""
    threshold = 0.70

    # Anomali tinggi + severity tinggi -> CRITICAL -> ESCALATE
    decision, action, escalate = evaluate_decision(
        anomaly_score=0.85, threshold=threshold, max_severity=10, alert_count=10, mitre_tactic_count=2
    )
    assert decision == "CRITICAL"
    assert action == "ESCALATE"
    assert escalate is True

    # Anomali tinggi + severity rendah (ada taktik MITRE atau count >= 5) -> SUSPICIOUS -> ESCALATE
    decision, action, escalate = evaluate_decision(
        anomaly_score=0.85, threshold=threshold, max_severity=4, alert_count=10, mitre_tactic_count=1
    )
    assert decision == "SUSPICIOUS"
    assert action == "ESCALATE"
    assert escalate is True

    # Anomali rendah + severity tinggi -> NOISE_HIGH -> DAILY_DIGEST
    decision, action, escalate = evaluate_decision(
        anomaly_score=0.50, threshold=threshold, max_severity=8, alert_count=10, mitre_tactic_count=0
    )
    assert decision == "NOISE_HIGH"
    assert action == "DAILY_DIGEST"
    assert escalate is False

    # Anomali rendah + severity rendah -> NOISE -> SUPPRESS
    decision, action, escalate = evaluate_decision(
        anomaly_score=0.40, threshold=threshold, max_severity=3, alert_count=2, mitre_tactic_count=0
    )
    assert decision == "NOISE"
    assert action == "SUPPRESS"
    assert escalate is False


def test_false_positive_gate_contextual_anomaly():
    """Bila anomaly_score >= threshold TETAPI max_severity < 7 DAN alert_count < 5 DAN mitre_tactic_count == 0,
    hasilnya harus CONTEXTUAL_ANOMALY -> SUPPRESS.
    """
    threshold = 0.70

    decision, action, escalate = evaluate_decision(
        anomaly_score=0.90,  # anomali tinggi
        threshold=threshold,
        max_severity=4,       # severity < 7
        alert_count=2,        # count < 5
        mitre_tactic_count=0, # tanpa taktik MITRE
    )
    assert decision == "CONTEXTUAL_ANOMALY"
    assert action == "SUPPRESS"
    assert escalate is False


def test_false_positive_gate_mitre_presence_prevents_suppression():
    """Bila mitre_tactic_count > 0, False Positive Gate TIDAK aktif meski count < 5 dan severity < 7."""
    threshold = 0.70

    decision, action, escalate = evaluate_decision(
        anomaly_score=0.90,
        threshold=threshold,
        max_severity=4,
        alert_count=2,
        mitre_tactic_count=1,  # ada MITRE -> lolos dari FP gate
    )
    assert decision == "SUSPICIOUS"
    assert action == "ESCALATE"
    assert escalate is True
