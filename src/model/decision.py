"""Decision Matrix dan False Positive Gate."""

from typing import Tuple


def evaluate_decision(
    anomaly_score: float,
    threshold: float,
    max_severity: int,
    alert_count: int,
    mitre_tactic_count: int,
) -> Tuple[str, str, bool]:
    """Tentukan keputusan operasional akhir dan tindakan untuk meta-alert terskor.

    Menerapkan False Positive Gate dan Decision Matrix 4 kuadran:

    False Positive Gate:
        if max_severity < 7 and alert_count < 5 and mitre_tactic_count == 0 and anomaly_score >= threshold:
            decision = CONTEXTUAL_ANOMALY
            action = SUPPRESS
            escalate = False

    Decision Matrix:
        anomaly_high (score >= threshold) & severity_high (max_severity >= 7):
            decision = CRITICAL, action = ESCALATE, escalate = True
        anomaly_high & severity_low:
            decision = SUSPICIOUS, action = ESCALATE, escalate = True
        anomaly_low & severity_high:
            decision = NOISE_HIGH, action = DAILY_DIGEST, escalate = False
        anomaly_low & severity_low:
            decision = NOISE, action = SUPPRESS, escalate = False

    Parameters
    ----------
    anomaly_score : float
        Skor anomali terkalibrasi.
    threshold : float
        Threshold Tukey milik model aktif.
    max_severity : int
        Level severity tertinggi dalam bucket.
    alert_count : int
        Jumlah raw alert dalam bucket.
    mitre_tactic_count : int
        Jumlah taktik MITRE unik dalam bucket.

    Returns
    -------
    Tuple[str, str, bool]
        (decision, action, escalate)
    """
    anomaly_high = anomaly_score >= threshold
    severity_high = max_severity >= 7

    # Cek False Positive Gate.
    if anomaly_high:
        if max_severity < 7 and alert_count < 5 and mitre_tactic_count == 0:
            return "CONTEXTUAL_ANOMALY", "SUPPRESS", False

        if severity_high:
            return "CRITICAL", "ESCALATE", True
        else:
            return "SUSPICIOUS", "ESCALATE", True
    else:
        if severity_high:
            return "NOISE_HIGH", "DAILY_DIGEST", False
        else:
            return "NOISE", "SUPPRESS", False
