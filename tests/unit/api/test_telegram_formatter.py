"""Unit test format pesan notifikasi Telegram."""
from datetime import datetime, timezone

from src.contracts.scored_meta_alert import ScoredMetaAlert
from src.api.telegram_formatter import format_telegram_alert


def _meta(**overrides):
    base = dict(
        meta_id=99,
        agent_id="001",
        agent_name="db-prod",
        rule_group_primary="sql_injection",
        start_time=datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc),
        end_time=datetime(2026, 8, 28, 10, 15, 0, tzinfo=timezone.utc),
        alert_count=25,
        max_severity=12,
        mitre_tactics=("Initial Access", "Impact"),
        seven_features={},
        raw_model_score=0.88,
        anomaly_score=0.95,
        threshold_used=0.68,
        decision="CRITICAL",
        action="ESCALATE",
        escalate=True,
        model_version="rbta-v1.0",
        feature_schema_version="1.0",
        score_calibration_version="minmax-v1",
        source_alert_ids=("a1", "a2"),
    )
    base.update(overrides)
    return ScoredMetaAlert(**base)


def test_telegram_formatter_hierarchy():
    """Pesan terbaca sebagai hirarki: vonis, identitas, konteks, skor, batas klaim."""
    msg = format_telegram_alert(_meta())

    assert "<b>CRITICAL · META-ALERT #99</b>" in msg
    assert "db-prod (001) · sql_injection" in msg
    assert "<b>Action: ESCALATE</b>" in msg
    assert "28 Agu 2026, 18:00-18:15 WITA" in msg
    assert "25 alert" in msg
    assert "12/15" in msg
    assert "Initial Access, Impact" in msg
    assert "0.9500" in msg
    assert "margin +0.2700" in msg
    assert "bukan bukti serangan" in msg
    # Seksi dipisah baris kosong agar renggang dibaca.
    assert "\n\n" in msg


def test_telegram_formatter_no_duplication_no_dense_labels():
    """Level tidak diulang di dua tempat; label teknis yang padat dihapus."""
    msg = format_telegram_alert(_meta())

    assert "Level:" not in msg
    assert "Evidence:" not in msg
    assert "Threshold:" not in msg
    assert "Anomaly:" not in msg
    assert msg.count("CRITICAL") == 1


def test_telegram_formatter_window_spanning_two_days():
    """Rentang beda hari ditulis penuh di kedua sisi."""
    msg = format_telegram_alert(
        _meta(end_time=datetime(2026, 8, 29, 2, 0, 0, tzinfo=timezone.utc))
    )

    assert "28 Agu 2026, 18:00" in msg
    assert "29 Agu 2026, 10:00" in msg
