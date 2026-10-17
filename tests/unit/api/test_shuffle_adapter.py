"""Unit test ShuffleWebhookForwarder."""
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
import pytest
import requests
from requests.exceptions import ReadTimeout

from src.contracts.scored_meta_alert import ScoredMetaAlert
from src.api.shuffle_adapter import ShuffleForwarderError, ShuffleWebhookForwarder


def make_scored_meta(meta_id: int) -> ScoredMetaAlert:
    return ScoredMetaAlert(
        meta_id=meta_id,
        agent_id="001",
        agent_name="soc-1",
        rule_group_primary="pam",
        start_time=datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc),
        end_time=datetime(2026, 8, 28, 10, 10, 0, tzinfo=timezone.utc),
        alert_count=5,
        max_severity=8,
        mitre_tactics=("Initial Access",),
        seven_features={},
        raw_model_score=0.72,
        anomaly_score=0.85,
        threshold_used=0.65,
        decision="CRITICAL",
        action="ESCALATE",
        escalate=True,
        model_version="v1",
        feature_schema_version="1.0",
        score_calibration_version="minmax-v1",
        source_alert_ids=("a1", "a2", "a3", "a4", "a5"),
    )


def test_shuffle_forwarder_sends_idempotent_event_header():
    """Forwarder mengirim payload dengan header X-Event-ID dan webhook key."""
    forwarder = ShuffleWebhookForwarder(
        webhook_url="https://shuffle.campus.local/api/v1/hooks/rbta_hook",
        api_key="shuffle-token-123",
    )
    meta = make_scored_meta(42)

    mock_resp = MagicMock()
    mock_resp.status_code = 200

    with patch("requests.Session.post", return_value=mock_resp) as mock_post:
        success = forwarder.forward(meta)
        assert success.success is True

        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        assert kwargs["headers"]["X-Event-ID"] == "rbta-meta-42"
        assert kwargs["headers"]["Authorization"] == "Bearer shuffle-token-123"
        assert kwargs["json"]["meta_id"] == 42
        assert kwargs["json"]["decision"] == "CRITICAL"


def test_shuffle_forwarder_idempotent_retry_on_lost_response():
    """Receiver menyimulasikan response hilang di percobaan 1; retry aman karena di-dedup lewat X-Event-ID."""
    forwarder = ShuffleWebhookForwarder(
        webhook_url="https://shuffle.campus.local/api/v1/hooks/rbta_hook",
        api_key="token-abc",
        sleep_fn=lambda _: None,  # sleep no-op
    )
    meta = make_scored_meta(42)

    processed_events = set()
    business_executions = 0

    def fake_receiver_post(url, headers=None, json=None, timeout=None, verify=None):
        nonlocal business_executions
        event_id = headers.get("X-Event-ID")

        # Cek apakah sudah pernah diproses.
        if event_id in processed_events:
            # Deteksi duplikat: tanpa efek samping bisnis, kembalikan 200 OK.
            mock_200 = MagicMock(status_code=200, text="Duplicate ignored")
            return mock_200

        # Percobaan pertama: jalankan aksi bisnis.
        processed_events.add(event_id)
        business_executions += 1

        # Simulasikan koneksi putus / timeout tepat setelah aksi bisnis.
        raise ReadTimeout("Connection dropped before response")

    with patch("requests.Session.post", side_effect=fake_receiver_post):
        result = forwarder.forward(meta)
        assert result.success is True
        assert result.attempts == 2
        assert result.status_code == 200
        # Aksi bisnis tetap dijalankan tepat sekali meskipun ada retry karena timeout.
        assert business_executions == 1


def test_shuffle_forwarder_retries_on_429_rate_limit():
    """Forwarder melakukan retry saat HTTP 429 dengan exponential backoff."""
    forwarder = ShuffleWebhookForwarder(
        webhook_url="https://shuffle.campus.local/api/v1/hooks/rbta_hook",
        sleep_fn=lambda _: None,
    )
    meta = make_scored_meta(99)

    resp_429 = MagicMock(status_code=429, text="Rate Limited")
    resp_200 = MagicMock(status_code=200, text="OK")

    with patch("requests.Session.post", side_effect=[resp_429, resp_200]) as mock_post:
        result = forwarder.forward(meta)
        assert result.success is True
        assert result.attempts == 2
        assert mock_post.call_count == 2

