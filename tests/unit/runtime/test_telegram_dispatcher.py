"""Unit test dispatcher Telegram live yang berdiri sendiri.

Cakupan dispatcher: thread terpisah yang membaca outbox service; hanya action == ESCALATE
yang dikirim lewat Telegram (keputusan terkunci); berhasil -> commit_outbox; gagal -> tetap
di outbox (tidak hilang, tidak terduplikasi); tanpa kredensial -> dry-run yang aman.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List

import pytest

from src.contracts.scored_meta_alert import ScoredMetaAlert
from src.runtime.telegram_dispatcher import TelegramDispatcher, make_telegram_sender



@pytest.fixture(autouse=True)
def _no_cooldown(monkeypatch):
    """Tes lama menguji perilaku per item; cooldown T10 diuji di test_escalation_cooldown.py."""
    monkeypatch.setenv("RBTA_ESCALATION_COOLDOWN_MIN", "0")


def _scored(
    meta_id: int,
    action: str = "ESCALATE",
    decision: str = "CRITICAL",
    end_time: datetime | None = None,
) -> ScoredMetaAlert:
    now = datetime.now(timezone.utc)
    end = end_time if end_time is not None else now
    start = end
    return ScoredMetaAlert(
        meta_id=meta_id,
        agent_id="001",
        agent_name="prod-wazuh-agent",
        rule_group_primary="authentication_failed",
        start_time=start,
        end_time=end,
        alert_count=12,
        max_severity=9,
        mitre_tactics=("credential-access",),
        seven_features={
            "max_severity": 9.0,
            "mitre_tactic_count": 1.0,
            "critical_mitre_tactic_present": 1.0,
            "alert_count_log": 2.4849,
            "rule_diversity_shannon": 0.85,
            "severity_dispersion": 0.72,
            "agent_criticality": 2.0,
        },
        raw_model_score=0.1523,
        anomaly_score=0.4215,
        threshold_used=0.4028,
        decision=decision,
        action=action,
        escalate=(action == "ESCALATE"),
        model_version="rbta-if-v1",
        feature_schema_version="1.0",
        score_calibration_version="minmax-v1",
        source_alert_ids=("alert-001",),
        metadata={},
    )


class _FakeService:
    """Double service minimal yang hanya menyediakan kontrak outbox."""

    def __init__(self, outbox: List[ScoredMetaAlert], live_source_state=None) -> None:
        self._outbox = list(outbox)
        self.committed: List[List[int]] = []
        self._live_source_state = live_source_state

    def get_outbox(self) -> List[ScoredMetaAlert]:
        return list(self._outbox)

    def commit_outbox(self, meta_ids: List[int]) -> int:
        before = len(self._outbox)
        self._outbox = [m for m in self._outbox if m.meta_id not in meta_ids]
        self.committed.append(list(meta_ids))
        return before - len(self._outbox)

    def get_live_source_state(self) -> dict:
        if self._live_source_state is None:
            return {}
        return dict(self._live_source_state)


class _NoStateMethodService:
    """Double service TANPA get_live_source_state (jalur fallback)."""

    def __init__(self, outbox: List[ScoredMetaAlert]) -> None:
        self._outbox = list(outbox)
        self.committed: List[List[int]] = []

    def get_outbox(self) -> List[ScoredMetaAlert]:
        return list(self._outbox)

    def commit_outbox(self, meta_ids: List[int]) -> int:
        before = len(self._outbox)
        self._outbox = [m for m in self._outbox if m.meta_id not in meta_ids]
        self.committed.append(list(meta_ids))
        return before - len(self._outbox)


class _RecordingManager:
    """state_manager tiruan yang menyediakan notification_add (+suppression_add)."""

    def __init__(self) -> None:
        self.notifications: list = []
        self.suppressions: list = []

    def notification_add(self, meta_id: int, run_id: str, verdict: str) -> None:
        self.notifications.append((meta_id, run_id, verdict))

    def suppression_add(self, meta_id: int, reason: str) -> None:
        self.suppressions.append((meta_id, reason))


def _sender_factory(behaviour: List[Any]):
    """Bangun sender yang bisa di-inject; setiap entri bernilai None (sukses) atau Exception yang dilempar."""
    calls: List[Dict[str, Any]] = []
    queue = list(behaviour)

    def send(payload: Dict[str, Any]) -> None:
        calls.append(payload)
        if not queue:
            return
        outcome = queue.pop(0)
        if isinstance(outcome, Exception):
            raise outcome

    send.calls = calls  # type: ignore[attr-defined]
    return send


def test_fail_then_success_sends_once_and_empties_outbox():
    now = datetime.now(timezone.utc)
    service = _FakeService([_scored(101, end_time=now)])
    send = _sender_factory([RuntimeError("flaky network"), None])
    dispatcher = TelegramDispatcher(
        service,
        sender=send,
        run_id="live",
        bot_token="tok",
        chat_id="chat",
        max_attempts=3,
        backoff_base_sec=0.0,
        bootstrap_started_at=now,
    )

    result = dispatcher.dispatch_once()

    assert result.sent == 1
    assert len(send.calls) == 2  # satu retry, lalu sukses
    assert service.get_outbox() == []
    assert service.committed == [[101]]
    payload = send.calls[-1]
    assert payload["meta_id"] == 101
    assert payload["idempotency_key"] == "live:101"
    # Decision dan action ditampilkan terpisah, tanpa label ganda.
    assert payload["decision"] == "CRITICAL"
    assert payload["action"] == "ESCALATE"
    assert "ESCALATE ESCALATE" not in payload["message"]


def test_persistent_failure_keeps_item_in_outbox_without_duplicate_send_record():
    now = datetime.now(timezone.utc)
    service = _FakeService([_scored(102, end_time=now)])
    send = _sender_factory([RuntimeError("down"), RuntimeError("down"), RuntimeError("down")])
    dispatcher = TelegramDispatcher(
        service,
        sender=send,
        run_id="live",
        bot_token="tok",
        chat_id="chat",
        max_attempts=3,
        backoff_base_sec=0.0,
        bootstrap_started_at=now,
    )

    result = dispatcher.dispatch_once()

    assert result.sent == 0
    assert result.failed == 1
    # Item TIDAK hilang dan TIDAK di-commit.
    assert [m.meta_id for m in service.get_outbox()] == [102]
    assert service.committed == []
    # Retry terjadi untuk item tunggal itu, tetapi hanya satu pesan logis.
    assert len(send.calls) == 3
    assert {c["idempotency_key"] for c in send.calls} == {"live:102"}


def test_non_escalate_items_are_skipped_and_left_in_outbox():
    service = _FakeService([_scored(103, action="SUPPRESS", decision="NOISE")])
    send = _sender_factory([])
    dispatcher = TelegramDispatcher(
        service, sender=send, run_id="live", bot_token="tok", chat_id="chat"
    )

    result = dispatcher.dispatch_once()

    assert result.sent == 0
    assert result.skipped == 1
    assert len(send.calls) == 0
    assert [m.meta_id for m in service.get_outbox()] == [103]


def test_missing_credentials_is_safe_dry_run(monkeypatch):
    monkeypatch.delenv("RBTA_TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("RBTA_TELEGRAM_CHAT_ID", raising=False)
    monkeypatch.delenv("RBTA_TELEGRAM_DRY_RUN", raising=False)
    now = datetime.now(timezone.utc)
    service = _FakeService([_scored(104, end_time=now)])
    send = _sender_factory([])
    dispatcher = TelegramDispatcher(
        service, sender=send, run_id="live", bootstrap_started_at=now, dry_run=True
    )

    assert dispatcher.enabled is False
    result = dispatcher.dispatch_once()

    assert result.dry_run == 1
    assert result.sent == 0
    assert len(send.calls) == 0
    # Dry-run menguras outbox (commit + kunci dedup), payload disimpan di buffer.
    assert service.get_outbox() == []
    assert service.committed == [[104]]


def test_already_sent_key_is_not_resent_in_same_dispatcher():
    now = datetime.now(timezone.utc)
    service = _FakeService([_scored(105, end_time=now)])
    send = _sender_factory([None])
    dispatcher = TelegramDispatcher(
        service,
        sender=send,
        run_id="live",
        bot_token="tok",
        chat_id="chat",
        bootstrap_started_at=now,
    )
    dispatcher.dispatch_once()
    # Item muncul lagi di outbox (mis. di-antrekan ulang setelah service restart).
    service._outbox.append(_scored(105, end_time=now))

    result = dispatcher.dispatch_once()

    assert result.sent == 0
    assert result.duplicate_skipped == 1
    assert len(send.calls) == 1


def _mock_session(response=None, error=None):
    """Session tiruan mirip requests; mencatat post tanpa akses jaringan."""
    from unittest.mock import MagicMock

    session = MagicMock()
    if error is not None:
        session.post.side_effect = error
    else:
        resp = MagicMock()
        resp.json.return_value = response
        session.post.return_value = resp
    return session


def _sender_payload(meta_id: int = 201) -> Dict[str, Any]:
    return {
        "meta_id": meta_id,
        "idempotency_key": f"live:{meta_id}",
        "chat_id": "chat-1",
        "message": "<b>test</b>",
        "parse_mode": "HTML",
    }


def test_make_sender_posts_to_bot_api_on_ok_true():
    session = _mock_session(response={"ok": True, "result": {"message_id": 7}})
    send = make_telegram_sender("tok-abc", session=session)

    send(_sender_payload())

    (url,), kwargs = session.post.call_args
    assert url == "https://api.telegram.org/bottok-abc/sendMessage"
    assert kwargs["json"]["chat_id"] == "chat-1"
    assert kwargs["json"]["text"] == "<b>test</b>"


def test_make_sender_raises_when_api_ok_false():
    session = _mock_session(response={"ok": False, "description": "blocked"})
    send = make_telegram_sender("tok-abc", session=session)

    with pytest.raises(RuntimeError, match="rejected"):
        send(_sender_payload())


def test_make_sender_raises_on_transport_error():
    import requests

    session = _mock_session(error=requests.exceptions.ConnectionError("down"))
    send = make_telegram_sender("tok-abc", session=session)

    with pytest.raises(RuntimeError, match="request failed"):
        send(_sender_payload())


def test_make_sender_refuses_payload_without_chat_id():
    session = _mock_session(response={"ok": True})
    send = make_telegram_sender("tok-abc", session=session)
    payload = _sender_payload()
    del payload["chat_id"]

    with pytest.raises(RuntimeError, match="chat_id"):
        send(payload)
    session.post.assert_not_called()


# Keamanan token, retry, dan rate limit.

def test_sender_sanitizes_token_url_from_error():
    import requests

    secret = "SECRET123TOKEN"
    session = _mock_session(
        error=requests.exceptions.ConnectionError(
            f"https://api.telegram.org/bot{secret}/sendMessage timed out"
        )
    )
    send = make_telegram_sender("tok-abc", session=session)

    with pytest.raises(RuntimeError) as excinfo:
        send(_sender_payload())
    assert secret not in str(excinfo.value)
    # Rantai exception tidak boleh membawa URL yang berisi token.
    assert excinfo.value.__cause__ is None


def test_sender_includes_http_status_without_url():
    import requests

    secret = "SECRET999TOKEN"
    err = requests.exceptions.HTTPError(
        f"https://api.telegram.org/bot{secret}/sendMessage 429"
    )
    resp = type("R", (), {"status_code": 429, "headers": {"Retry-After": "2"}})()
    err.response = resp  # type: ignore[attr-defined]
    session = _mock_session(error=err)
    send = make_telegram_sender("tok-abc", session=session)

    with pytest.raises(RuntimeError) as excinfo:
        send(_sender_payload())
    assert secret not in str(excinfo.value)
    assert "429" in str(excinfo.value)


def test_dispatcher_log_never_contains_token(caplog):
    import logging

    secret = "LEAKEDTOKEN456"
    now = datetime.now(timezone.utc)
    service = _FakeService([_scored(301, end_time=now)])
    send = _sender_factory(
        [RuntimeError(f"GET https://api.telegram.org/bot{secret}/sendMessage failed")]
        * 3
    )
    dispatcher = TelegramDispatcher(
        service,
        sender=send,
        run_id="live",
        bot_token="tok",
        chat_id="chat",
        max_attempts=3,
        backoff_base_sec=0.0,
        bootstrap_started_at=now,
    )
    with caplog.at_level(logging.WARNING, logger="src.runtime.telegram_dispatcher"):
        dispatcher.dispatch_once()
    assert secret not in caplog.text


def test_historical_item_suppressed_but_committed():
    from datetime import timedelta

    now = datetime.now(timezone.utc)
    bootstrap = now
    old = bootstrap - timedelta(seconds=7200)
    service = _FakeService([_scored(401, end_time=old)])
    send = _sender_factory([])
    dispatcher = TelegramDispatcher(
        service,
        sender=send,
        run_id="live",
        bot_token="tok",
        chat_id="chat",
        notify_max_age_sec=3600,
        bootstrap_started_at=bootstrap,
        sleep_fn=lambda s: None,
    )
    result = dispatcher.dispatch_once()
    assert result.sent == 0
    assert len(send.calls) == 0
    assert service.get_outbox() == []
    assert service.committed == [[401]]
    assert dispatcher.status()["suppressed_historical_total"] == 1


def test_max_age_reads_env(monkeypatch):
    from datetime import timedelta

    now = datetime.now(timezone.utc)
    old = now - timedelta(seconds=7200)
    monkeypatch.setenv("RBTA_TELEGRAM_NOTIFY_MAX_AGE_SEC", "60")
    service = _FakeService([_scored(402, end_time=old)])
    send = _sender_factory([])
    dispatcher = TelegramDispatcher(
        service,
        sender=send,
        run_id="live",
        bot_token="tok",
        chat_id="chat",
        bootstrap_started_at=now,
        sleep_fn=lambda s: None,
    )
    dispatcher.dispatch_once()
    assert dispatcher.status()["suppressed_historical_total"] == 1
    assert service.get_outbox() == []


def test_docstring_is_honest_about_at_least_once():
    import src.runtime.telegram_dispatcher as mod

    assert "at-least-once" in mod.__doc__


def test_duplicate_still_commits_to_unstick_item():
    now = datetime.now(timezone.utc)
    service = _FakeService([_scored(105, end_time=now)])
    send = _sender_factory([None])
    dispatcher = TelegramDispatcher(
        service,
        sender=send,
        run_id="live",
        bot_token="tok",
        chat_id="chat",
        sleep_fn=lambda s: None,
        bootstrap_started_at=now,
    )
    dispatcher.dispatch_once()
    service._outbox.append(_scored(105, end_time=now))

    result = dispatcher.dispatch_once()

    assert result.duplicate_skipped == 1
    assert len(send.calls) == 1
    assert service.committed == [[105], [105]]
    assert service.get_outbox() == []


def test_formatter_shows_meta_id():
    from src.runtime.telegram_formatter import format_telegram_alert

    text = format_telegram_alert(_scored(999), run_id="live")
    assert "999" in text
    assert "META-ALERT" in text


def test_throttle_sleeps_between_successful_sends():
    sleeps: list = []
    now = datetime.now(timezone.utc)
    service = _FakeService([_scored(501, end_time=now), _scored(502, end_time=now)])
    send = _sender_factory([None, None])
    dispatcher = TelegramDispatcher(
        service,
        sender=send,
        run_id="live",
        bot_token="tok",
        chat_id="chat",
        sleep_fn=sleeps.append,
        bootstrap_started_at=now,
    )
    result = dispatcher.dispatch_once()
    assert result.sent == 2
    assert any(s >= 0.9 for s in sleeps)


def test_429_retry_after_is_honored():
    sleeps: list = []

    calls: list = []

    def send(payload):
        calls.append(payload)
        if len(calls) == 1:
            err = RuntimeError("Transport failed")
            err.http_status = 429  # type: ignore[attr-defined]
            err.retry_after_sec = 5.0  # type: ignore[attr-defined]
            raise err

    now = datetime.now(timezone.utc)
    service = _FakeService([_scored(601, end_time=now)])
    dispatcher = TelegramDispatcher(
        service,
        sender=send,
        run_id="live",
        bot_token="tok",
        chat_id="chat",
        max_attempts=3,
        backoff_base_sec=0.0,
        sleep_fn=sleeps.append,
        bootstrap_started_at=now,
    )
    result = dispatcher.dispatch_once()
    assert result.sent == 1
    assert any(abs(s - 5.0) < 1e-9 for s in sleeps)


def test_status_exposes_required_counters():
    now = datetime.now(timezone.utc)
    service = _FakeService([_scored(701, end_time=now)])
    send = _sender_factory([None])
    dispatcher = TelegramDispatcher(
        service,
        sender=send,
        run_id="live",
        bot_token="tok",
        chat_id="chat",
        sleep_fn=lambda s: None,
        bootstrap_started_at=now,
    )
    dispatcher.dispatch_once()
    st = dispatcher.status()
    assert st == {
        "sent_total": 1,
        "failed_total": 0,
        "suppressed_historical_total": 0,
        "dry_run_total": 0,
        "suppressed_cooldown_total": 0,
        "cooldown_min": 0.0,
        "mode": "live",
    }


# Penahanan alert historis, dry-run, dan dedup.

def test_historical_suppressed_against_bootstrap_time():
    from datetime import timedelta

    now = datetime.now(timezone.utc)
    bootstrap = now
    old = bootstrap - timedelta(seconds=7200)
    service = _FakeService([_scored(801, end_time=old)])
    send = _sender_factory([])
    dispatcher = TelegramDispatcher(
        service,
        sender=send,
        run_id="live",
        bot_token="tok",
        chat_id="chat",
        notify_max_age_sec=3600,
        bootstrap_started_at=bootstrap,
        sleep_fn=lambda s: None,
    )
    result = dispatcher.dispatch_once()
    assert result.sent == 0
    assert result.suppressed_historical == 1
    assert len(send.calls) == 0
    assert service.get_outbox() == []
    assert service.committed == [[801]]
    assert dispatcher.status()["suppressed_historical_total"] == 1


def test_no_bootstrap_means_fail_closed_no_send_no_commit(caplog):
    """Bootstrap yang tidak diketahui gagal tertutup — item dilewati, outbox dipertahankan."""
    import logging

    from datetime import timedelta

    now = datetime.now(timezone.utc)
    old = now - timedelta(seconds=7200)
    # _NoStateMethodService sama sekali tidak punya get_live_source_state.
    service = _NoStateMethodService([_scored(802, end_time=old)])
    send = _sender_factory([None])
    dispatcher = TelegramDispatcher(
        service,
        sender=send,
        run_id="live",
        bot_token="tok",
        chat_id="chat",
        notify_max_age_sec=3600,
        bootstrap_started_at=None,
        sleep_fn=lambda s: None,
    )
    with caplog.at_level(logging.WARNING, logger="src.runtime.telegram_dispatcher"):
        result = dispatcher.dispatch_once()
    assert result.sent == 0
    assert result.suppressed_historical == 0
    assert result.skipped == 1
    assert len(send.calls) == 0
    # Outbox dipertahankan: tidak ada yang di-commit.
    assert [m.meta_id for m in service.get_outbox()] == [802]
    assert service.committed == []
    assert "fail-closed" in caplog.text


def test_recent_item_after_bootstrap_cutoff_is_sent():
    from datetime import timedelta

    now = datetime.now(timezone.utc)
    bootstrap = now - timedelta(seconds=100)
    recent = bootstrap - timedelta(seconds=100)  # masih dalam toleransi 3600
    service = _FakeService([_scored(803, end_time=recent)])
    send = _sender_factory([None])
    dispatcher = TelegramDispatcher(
        service,
        sender=send,
        run_id="live",
        bot_token="tok",
        chat_id="chat",
        notify_max_age_sec=3600,
        bootstrap_started_at=bootstrap,
        sleep_fn=lambda s: None,
    )
    result = dispatcher.dispatch_once()
    assert result.sent == 1
    assert result.suppressed_historical == 0


def test_missing_end_time_never_suppressed():
    from types import SimpleNamespace

    now = datetime.now(timezone.utc)
    service = _FakeService([])
    dispatcher = TelegramDispatcher(
        service,
        sender=_sender_factory([]),
        run_id="live",
        bot_token="tok",
        chat_id="chat",
        bootstrap_started_at=now,
        sleep_fn=lambda s: None,
    )
    # end_time tidak valid/tidak ada tidak pernah menahan (tetap dikirim)
    assert dispatcher._is_historical(SimpleNamespace(end_time=None)) is False
    assert dispatcher._is_historical(SimpleNamespace()) is False
    assert dispatcher._is_historical(SimpleNamespace(end_time="not-a-datetime")) is False


def test_suppressed_item_recorded_via_state_manager_when_present():
    from datetime import timedelta

    now = datetime.now(timezone.utc)
    bootstrap = now
    old = bootstrap - timedelta(seconds=7200)
    service = _FakeService([_scored(805, end_time=old)])
    recorded: list = []

    class _SM:
        def notification_add(self, meta_id: int, run_id: str, verdict: str) -> None:
            recorded.append((meta_id, run_id, verdict))

    service.state_manager = _SM()  # type: ignore[attr-defined]
    send = _sender_factory([])
    dispatcher = TelegramDispatcher(
        service,
        sender=send,
        run_id="live",
        bot_token="tok",
        chat_id="chat",
        bootstrap_started_at=bootstrap,
        sleep_fn=lambda s: None,
    )
    dispatcher.dispatch_once()
    # Satu sumber: putusan penahanan hanya ada di notification_log.
    assert recorded == [(805, "live", "SUPPRESSED_HISTORICAL")]
    assert service.get_outbox() == []


def test_traceback_and_logs_never_contain_token(caplog):
    import logging
    import traceback

    import src.runtime.telegram_dispatcher as mod

    secret = "N3TOKEN999SECRET"
    session = _mock_session(
        error=RuntimeError(f"https://api.telegram.org/bot{secret}/sendMessage down")
    )
    send = mod.make_telegram_sender("tok-abc", session=session)
    with pytest.raises(RuntimeError) as excinfo:
        send(_sender_payload())
    text = "".join(traceback.format_exception(excinfo.value))
    assert secret not in text
    assert excinfo.value.__cause__ is None
    # jalur log dispatcher juga bebas token
    now = datetime.now(timezone.utc)
    service = _FakeService([_scored(806, end_time=now)])
    bad = _sender_factory(
        [RuntimeError(f"GET https://api.telegram.org/bot{secret}/sendMessage failed")] * 3
    )
    dispatcher = mod.TelegramDispatcher(
        service,
        sender=bad,
        run_id="live",
        bot_token="tok",
        chat_id="chat",
        max_attempts=3,
        backoff_base_sec=0.0,
        bootstrap_started_at=now,
    )
    with caplog.at_level(logging.WARNING, logger="src.runtime.telegram_dispatcher"):
        dispatcher.dispatch_once()
    assert secret not in caplog.text
    assert logging.getLogger("urllib3").level >= logging.WARNING


def test_dry_run_drains_outbox_and_dedups_across_passes(monkeypatch):
    monkeypatch.delenv("RBTA_TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("RBTA_TELEGRAM_CHAT_ID", raising=False)
    monkeypatch.delenv("RBTA_TELEGRAM_DRY_RUN", raising=False)
    now = datetime.now(timezone.utc)
    service = _FakeService([_scored(807, end_time=now)])
    send = _sender_factory([])
    dispatcher = TelegramDispatcher(
        service, sender=send, run_id="live", bootstrap_started_at=now, dry_run=True
    )
    assert dispatcher.enabled is False
    result = dispatcher.dispatch_once()
    assert result.dry_run == 1
    assert service.get_outbox() == []
    assert service.committed == [[807]]
    assert "live:807" in dispatcher._sent_keys
    # item muncul lagi -> duplicate_skipped, bukan dry_run lagi
    service._outbox.append(_scored(807, end_time=now))
    result2 = dispatcher.dispatch_once()
    assert result2.duplicate_skipped == 1
    assert result2.dry_run == 0
    assert dispatcher.status()["dry_run_total"] == 1


def test_dry_run_payloads_capped_at_50(monkeypatch):
    monkeypatch.delenv("RBTA_TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("RBTA_TELEGRAM_CHAT_ID", raising=False)
    monkeypatch.delenv("RBTA_TELEGRAM_DRY_RUN", raising=False)
    now = datetime.now(timezone.utc)
    service = _FakeService([_scored(i, end_time=now) for i in range(900, 960)])
    send = _sender_factory([])
    dispatcher = TelegramDispatcher(
        service, sender=send, run_id="live", bootstrap_started_at=now, dry_run=True
    )
    result = dispatcher.dispatch_once()
    assert result.dry_run == 60
    assert len(dispatcher.dry_run_payloads) == 50
    assert dispatcher.status()["dry_run_total"] == 60
    assert service.get_outbox() == []


def test_sent_keys_evicts_fifo_at_10000():
    service = _FakeService([])
    dispatcher = TelegramDispatcher(
        service, sender=_sender_factory([]), run_id="live", bot_token="t", chat_id="c"
    )
    for i in range(10000):
        dispatcher._remember_sent_key(f"live:{i}")
    assert len(dispatcher._sent_keys) == 10000
    dispatcher._remember_sent_key("live:new")
    assert len(dispatcher._sent_keys) == 10000
    assert "live:new" in dispatcher._sent_keys
    assert "live:0" not in dispatcher._sent_keys


def test_retry_after_falls_back_to_body_parameters():
    import requests

    err = requests.exceptions.HTTPError("429 slow down")
    resp = type(
        "R",
        (),
        {
            "status_code": 429,
            "headers": {},
            "json": lambda self: {"ok": False, "parameters": {"retry_after": 7}},
        },
    )()
    err.response = resp  # type: ignore[attr-defined]
    from src.runtime.telegram_dispatcher import _retry_after_of

    assert _retry_after_of(err) == 7.0


def test_cycle_chain_terminates():
    from src.runtime.telegram_dispatcher import _http_status_of, _retry_after_of

    err = RuntimeError("cycle")
    err.__cause__ = err  # type: ignore[assignment]
    assert _http_status_of(err) is None
    assert _retry_after_of(err) is None


# Bootstrap lazy + gagal tertutup.

def test_explicit_param_wins_over_state_key():
    from datetime import timedelta

    now = datetime.now(timezone.utc)
    ancient = now - timedelta(seconds=7200)
    # State menyebut bootstrap sudah lama (akan menahan), parameter eksplisit masih baru.
    service = _FakeService(
        [_scored(811, end_time=now)],
        live_source_state={"live_first_started_at": ancient.isoformat()},
    )
    send = _sender_factory([None])
    dispatcher = TelegramDispatcher(
        service,
        sender=send,
        run_id="live",
        bot_token="tok",
        chat_id="chat",
        notify_max_age_sec=3600,
        bootstrap_started_at=now,
        sleep_fn=lambda s: None,
    )
    result = dispatcher.dispatch_once()
    assert result.sent == 1
    assert result.suppressed_historical == 0


def test_state_key_iso_string_used_when_no_param():
    from datetime import timedelta

    now = datetime.now(timezone.utc)
    bootstrap = now
    old = bootstrap - timedelta(seconds=7200)
    service = _FakeService(
        [_scored(812, end_time=old)],
        live_source_state={"live_first_started_at": bootstrap.isoformat()},
    )
    send = _sender_factory([])
    dispatcher = TelegramDispatcher(
        service,
        sender=send,
        run_id="live",
        bot_token="tok",
        chat_id="chat",
        notify_max_age_sec=3600,
        sleep_fn=lambda s: None,
    )
    result = dispatcher.dispatch_once()
    assert result.sent == 0
    assert result.suppressed_historical == 1
    assert service.get_outbox() == []
    assert service.committed == [[812]]


def test_warning_logged_once_per_pass_when_unknown(caplog):
    import logging

    from datetime import timedelta

    now = datetime.now(timezone.utc)
    old = now - timedelta(seconds=7200)
    service = _NoStateMethodService(
        [_scored(813, end_time=old), _scored(814, end_time=old)]
    )
    dispatcher = TelegramDispatcher(
        service,
        sender=_sender_factory([]),
        run_id="live",
        bot_token="tok",
        chat_id="chat",
        sleep_fn=lambda s: None,
    )
    with caplog.at_level(logging.WARNING, logger="src.runtime.telegram_dispatcher"):
        result = dispatcher.dispatch_once()
    assert result.skipped == 2
    assert service.committed == []
    warnings = [r for r in caplog.records if "fail-closed" in r.getMessage()]
    assert len(warnings) == 1


def test_invalid_state_value_fails_closed():
    now = datetime.now(timezone.utc)
    service = _FakeService(
        [_scored(815, end_time=now)],
        live_source_state={"live_first_started_at": "not-a-datetime"},
    )
    send = _sender_factory([None])
    dispatcher = TelegramDispatcher(
        service,
        sender=send,
        run_id="live",
        bot_token="tok",
        chat_id="chat",
        sleep_fn=lambda s: None,
    )
    result = dispatcher.dispatch_once()
    assert result.sent == 0
    assert len(send.calls) == 0
    assert [m.meta_id for m in service.get_outbox()] == [815]
    assert service.committed == []


def test_raising_state_getter_fails_closed():
    now = datetime.now(timezone.utc)
    service = _FakeService([_scored(816, end_time=now)])

    def _boom():
        raise RuntimeError("state store down")

    service.get_live_source_state = _boom  # type: ignore[method-assign]
    send = _sender_factory([None])
    dispatcher = TelegramDispatcher(
        service,
        sender=send,
        run_id="live",
        bot_token="tok",
        chat_id="chat",
        sleep_fn=lambda s: None,
    )
    result = dispatcher.dispatch_once()
    assert result.sent == 0
    assert len(send.calls) == 0
    assert [m.meta_id for m in service.get_outbox()] == [816]
    assert service.committed == []


def test_tolerance_boundary_recent_item_still_sent_old_suppressed():
    from datetime import timedelta

    now = datetime.now(timezone.utc)
    bootstrap = now
    # Batas desain: ESCALATE yang berakhir <1 jam sebelum bootstrap tetap dikirim.
    recent = bootstrap - timedelta(seconds=3599)
    old = bootstrap - timedelta(seconds=3601)
    service = _FakeService([_scored(817, end_time=recent), _scored(818, end_time=old)])
    send = _sender_factory([None])
    dispatcher = TelegramDispatcher(
        service,
        sender=send,
        run_id="live",
        bot_token="tok",
        chat_id="chat",
        notify_max_age_sec=3600,
        bootstrap_started_at=bootstrap,
        sleep_fn=lambda s: None,
    )
    result = dispatcher.dispatch_once()
    assert result.sent == 1
    assert result.suppressed_historical == 1
    assert [c["meta_id"] for c in send.calls] == [817]
    assert service.committed == [[817], [818]]


# Putusan notification_add yang durable.

def test_sent_records_notification_add():
    now = datetime.now(timezone.utc)
    service = _FakeService([_scored(821, end_time=now)])
    manager = _RecordingManager()
    service.state_manager = manager  # type: ignore[attr-defined]
    dispatcher = TelegramDispatcher(
        service,
        sender=_sender_factory([None]),
        run_id="live",
        bot_token="tok",
        chat_id="chat",
        sleep_fn=lambda s: None,
        bootstrap_started_at=now,
    )
    result = dispatcher.dispatch_once()
    assert result.sent == 1
    assert manager.notifications == [(821, "live", "SENT")]


def test_dry_run_records_notification_add(monkeypatch):
    monkeypatch.delenv("RBTA_TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("RBTA_TELEGRAM_CHAT_ID", raising=False)
    monkeypatch.delenv("RBTA_TELEGRAM_DRY_RUN", raising=False)
    now = datetime.now(timezone.utc)
    service = _FakeService([_scored(822, end_time=now)])
    manager = _RecordingManager()
    service.state_manager = manager  # type: ignore[attr-defined]
    dispatcher = TelegramDispatcher(
        service,
        sender=_sender_factory([]),
        run_id="live",
        bootstrap_started_at=now,
        dry_run=True,
    )
    result = dispatcher.dispatch_once()
    assert result.dry_run == 1
    assert manager.notifications == [(822, "live", "DRY_RUN")]


def test_suppressed_records_notification_add():
    from datetime import timedelta

    now = datetime.now(timezone.utc)
    old = now - timedelta(seconds=7200)
    service = _FakeService([_scored(823, end_time=old)])
    manager = _RecordingManager()
    service.state_manager = manager  # type: ignore[attr-defined]
    dispatcher = TelegramDispatcher(
        service,
        sender=_sender_factory([]),
        run_id="live",
        bot_token="tok",
        chat_id="chat",
        bootstrap_started_at=now,
        sleep_fn=lambda s: None,
    )
    result = dispatcher.dispatch_once()
    assert result.suppressed_historical == 1
    assert manager.notifications == [(823, "live", "SUPPRESSED_HISTORICAL")]
    # Satu putusan: penahanan historis hanya ada di notification_log.
    assert manager.suppressions == []


def test_fallback_without_notification_add_method_still_sends():
    from types import SimpleNamespace

    now = datetime.now(timezone.utc)
    service = _FakeService([_scored(824, end_time=now)])
    service.state_manager = SimpleNamespace()  # type: ignore[attr-defined]
    dispatcher = TelegramDispatcher(
        service,
        sender=_sender_factory([None]),
        run_id="live",
        bot_token="tok",
        chat_id="chat",
        sleep_fn=lambda s: None,
        bootstrap_started_at=now,
    )
    result = dispatcher.dispatch_once()
    assert result.sent == 1
    assert service.committed == [[824]]


def test_fallback_without_state_manager_still_sends():
    now = datetime.now(timezone.utc)
    service = _FakeService([_scored(825, end_time=now)])
    assert not hasattr(service, "state_manager")
    dispatcher = TelegramDispatcher(
        service,
        sender=_sender_factory([None]),
        run_id="live",
        bot_token="tok",
        chat_id="chat",
        sleep_fn=lambda s: None,
        bootstrap_started_at=now,
    )
    result = dispatcher.dispatch_once()
    assert result.sent == 1
    assert service.committed == [[825]]


# Header Retry-After dan batas kedalaman.

def test_chain_scan_depth_is_8():
    import src.runtime.telegram_dispatcher as mod

    assert mod._CHAIN_SCAN_DEPTH == 8


def test_retry_after_exact_header_wins():
    err = RuntimeError("429 slow down")
    err.retry_after_sec = 9.0  # type: ignore[attr-defined]
    resp = type(
        "R",
        (),
        {"status_code": 429, "headers": {"Retry-After": "3"}},
    )()
    err.response = resp  # type: ignore[attr-defined]
    from src.runtime.telegram_dispatcher import _retry_after_of

    # Atribut langsung tetap mengalahkan header (urutan prioritas tidak berubah).
    assert _retry_after_of(err) == 9.0
    del err.retry_after_sec  # type: ignore[attr-defined]
    assert _retry_after_of(err) == 3.0


def test_retry_after_lowercase_header_only_is_ignored():
    class _Resp:
        status_code = 429
        headers = {"retry-after": "5"}

        def json(self):
            raise ValueError("no json body")

    err = RuntimeError("429 slow down")
    err.response = _Resp()  # type: ignore[attr-defined]
    from src.runtime.telegram_dispatcher import _retry_after_of

    assert _retry_after_of(err) is None


# Sleep default bisa diinterupsi lewat stop_event.

def test_default_sleep_stop_is_fast():
    service = _FakeService([])
    dispatcher = TelegramDispatcher(
        service,
        sender=_sender_factory([]),
        run_id="live",
        bot_token="tok",
        chat_id="chat",
        poll_interval_sec=3600.0,
    )
    # sleep_fn=None default memakai stop_event.wait yang bisa diinterupsi ...
    assert dispatcher._sleep == dispatcher._stop_event.wait
    # ... sedangkan sleep_fn eksplisit dipakai apa adanya.
    probe = lambda s: None
    explicit = TelegramDispatcher(
        service, sender=_sender_factory([]), run_id="live", sleep_fn=probe
    )
    assert explicit._sleep is probe
    dispatcher.start()
    thread = dispatcher._thread
    assert thread is not None
    dispatcher.stop(timeout_sec=5.0)
    assert not thread.is_alive()


# Dry-run eksplisit vs hold karena kredensial.

def test_missing_credentials_without_flag_holds_outbox(monkeypatch, caplog):
    import logging

    monkeypatch.delenv("RBTA_TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("RBTA_TELEGRAM_CHAT_ID", raising=False)
    monkeypatch.delenv("RBTA_TELEGRAM_DRY_RUN", raising=False)
    now = datetime.now(timezone.utc)
    service = _FakeService([_scored(901, end_time=now), _scored(902, end_time=now)])
    send = _sender_factory([])
    dispatcher = TelegramDispatcher(
        service,
        sender=send,
        run_id="live",
        bootstrap_started_at=now,
        sleep_fn=lambda s: None,
    )
    assert dispatcher.mode == "hold"
    with caplog.at_level(logging.WARNING, logger="src.runtime.telegram_dispatcher"):
        result = dispatcher.dispatch_once()
    assert result.skipped == 2
    assert result.sent == 0
    assert result.dry_run == 0
    assert len(send.calls) == 0
    # Outbox dipertahankan: tidak ada yang di-commit.
    assert [m.meta_id for m in service.get_outbox()] == [901, 902]
    assert service.committed == []
    assert dispatcher.status()["mode"] == "hold"
    hold_warnings = [r for r in caplog.records if "holding outbox" in r.getMessage()]
    assert len(hold_warnings) == 1


def test_explicit_dry_run_param_drains_and_records(monkeypatch):
    monkeypatch.delenv("RBTA_TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("RBTA_TELEGRAM_CHAT_ID", raising=False)
    monkeypatch.delenv("RBTA_TELEGRAM_DRY_RUN", raising=False)
    now = datetime.now(timezone.utc)
    service = _FakeService([_scored(903, end_time=now)])
    manager = _RecordingManager()
    service.state_manager = manager  # type: ignore[attr-defined]
    dispatcher = TelegramDispatcher(
        service,
        sender=_sender_factory([]),
        run_id="live",
        bootstrap_started_at=now,
        dry_run=True,
        sleep_fn=lambda s: None,
    )
    assert dispatcher.mode == "dry_run"
    result = dispatcher.dispatch_once()
    assert result.dry_run == 1
    assert service.get_outbox() == []
    assert service.committed == [[903]]
    assert manager.notifications == [(903, "live", "DRY_RUN")]
    assert manager.suppressions == []


def test_dry_run_env_flag_drains_without_param(monkeypatch):
    monkeypatch.delenv("RBTA_TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("RBTA_TELEGRAM_CHAT_ID", raising=False)
    monkeypatch.setenv("RBTA_TELEGRAM_DRY_RUN", "true")
    now = datetime.now(timezone.utc)
    service = _FakeService([_scored(904, end_time=now)])
    dispatcher = TelegramDispatcher(
        service,
        sender=_sender_factory([]),
        run_id="live",
        bootstrap_started_at=now,
        sleep_fn=lambda s: None,
    )
    assert dispatcher.mode == "dry_run"
    result = dispatcher.dispatch_once()
    assert result.dry_run == 1
    assert service.get_outbox() == []


def test_live_mode_with_credentials(monkeypatch):
    monkeypatch.delenv("RBTA_TELEGRAM_DRY_RUN", raising=False)
    now = datetime.now(timezone.utc)
    service = _FakeService([_scored(905, end_time=now)])
    dispatcher = TelegramDispatcher(
        service,
        sender=_sender_factory([None]),
        run_id="live",
        bot_token="tok",
        chat_id="chat",
        bootstrap_started_at=now,
        sleep_fn=lambda s: None,
    )
    assert dispatcher.mode == "live"
    assert dispatcher.status()["mode"] == "live"


# Penahanan terpadu + catat sebelum commit.

def test_unified_historical_suppression_only_notification_log():
    from datetime import timedelta

    now = datetime.now(timezone.utc)
    old = now - timedelta(seconds=7200)
    service = _FakeService([_scored(906, end_time=old)])
    manager = _RecordingManager()
    service.state_manager = manager  # type: ignore[attr-defined]
    dispatcher = TelegramDispatcher(
        service,
        sender=_sender_factory([]),
        run_id="live",
        bot_token="tok",
        chat_id="chat",
        bootstrap_started_at=now,
        sleep_fn=lambda s: None,
    )
    result = dispatcher.dispatch_once()
    assert result.suppressed_historical == 1
    assert manager.notifications == [(906, "live", "SUPPRESSED_HISTORICAL")]
    assert manager.suppressions == []
    assert service.get_outbox() == []


def test_record_failure_skips_commit_sent_path():
    now = datetime.now(timezone.utc)
    service = _FakeService([_scored(907, end_time=now)])

    class _Boom:
        def notification_add(self, meta_id: int, run_id: str, verdict: str) -> None:
            raise RuntimeError("store down")

    service.state_manager = _Boom()  # type: ignore[attr-defined]
    dispatcher = TelegramDispatcher(
        service,
        sender=_sender_factory([None]),
        run_id="live",
        bot_token="tok",
        chat_id="chat",
        bootstrap_started_at=now,
        sleep_fn=lambda s: None,
    )
    result = dispatcher.dispatch_once()
    assert result.failed == 1
    assert result.sent == 0
    assert [m.meta_id for m in service.get_outbox()] == [907]
    assert service.committed == []


def test_record_failure_skips_commit_dry_run_path(monkeypatch):
    monkeypatch.delenv("RBTA_TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("RBTA_TELEGRAM_CHAT_ID", raising=False)
    monkeypatch.delenv("RBTA_TELEGRAM_DRY_RUN", raising=False)
    now = datetime.now(timezone.utc)
    service = _FakeService([_scored(908, end_time=now)])

    class _Boom:
        def notification_add(self, meta_id: int, run_id: str, verdict: str) -> None:
            raise RuntimeError("store down")

    service.state_manager = _Boom()  # type: ignore[attr-defined]
    dispatcher = TelegramDispatcher(
        service,
        sender=_sender_factory([]),
        run_id="live",
        bootstrap_started_at=now,
        dry_run=True,
        sleep_fn=lambda s: None,
    )
    result = dispatcher.dispatch_once()
    assert result.failed == 1
    assert result.dry_run == 0
    assert [m.meta_id for m in service.get_outbox()] == [908]
    assert service.committed == []


# Interval throttle lewat env.

def test_min_interval_env_zero_disables_throttle(monkeypatch):
    monkeypatch.setenv("RBTA_TELEGRAM_MIN_INTERVAL_SEC", "0")
    monkeypatch.delenv("RBTA_TELEGRAM_DRY_RUN", raising=False)
    sleeps: list = []
    now = datetime.now(timezone.utc)
    service = _FakeService([_scored(909, end_time=now), _scored(910, end_time=now)])
    dispatcher = TelegramDispatcher(
        service,
        sender=_sender_factory([None, None]),
        run_id="live",
        bot_token="tok",
        chat_id="chat",
        sleep_fn=sleeps.append,
        bootstrap_started_at=now,
    )
    result = dispatcher.dispatch_once()
    assert result.sent == 2
    assert sleeps == []
