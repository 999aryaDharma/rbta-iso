"""Client custom API harus mem-paginasi {events,total,limit,offset} menjadi alert kanonis."""

from unittest.mock import MagicMock, patch

from src.etl.wazuh_canonicalizer import canonicalize_wazuh_alert
from src.ingestion.flat_api_adapter import flat_api_page_to_raw_list
from src.ingestion.wazuh_api_client import WazuhAPIClient


def _evt(i):
    return {
        "id": f"evt-{i}",
        "timestamp": "2026-10-03T01:37:15.128000Z",
        "agent_id": "005",
        "agent_name": "rbta-arya",
        "rule_id": "510",
        "rule_description": "Host-based anomaly detection event (rootcheck).",
        "rule_level": 7,
        "rule_groups": ["ossec", "rootcheck"],
        "location": "rootcheck",
        "decoder": None,
        "message": f"File '/dev/.lxc/proc/{i}' present on /dev.",
        "details": {"manager": {"name": "wazuh.manager"}},
    }


def test_page_helper_maps_events():
    page = {"events": [_evt(1), _evt(2)], "total": 3, "limit": 50, "offset": 0}
    raws = flat_api_page_to_raw_list(page)
    assert len(raws) == 2
    assert canonicalize_wazuh_alert(raws[0]).wazuh_alert_id == "evt-1"


def test_client_paginates_limit_offset_until_total():
    client = WazuhAPIClient(base_url="https://api-kampus:55000", api_key="k")
    pages = [
        {"events": [_evt(1), _evt(2)], "total": 3, "limit": 2, "offset": 0},
        {"events": [_evt(3)], "total": 3, "limit": 2, "offset": 2},
    ]
    with patch.object(client, "fetch_page", side_effect=pages) as fetch:
        alerts = client.fetch_all_canonical(limit=2)
    assert [a.wazuh_alert_id for a in alerts] == ["evt-1", "evt-2", "evt-3"]
    assert fetch.call_count == 2


def test_client_auth_failure_is_fail_fast_without_body():
    client = WazuhAPIClient(base_url="https://api-kampus:55000", api_key="bad")
    resp = MagicMock(status_code=401, text="secret-body-marker")
    with patch.object(client._session, "request", return_value=resp):
        try:
            client.fetch_page(limit=50, offset=0)
        except Exception as exc:
            assert "secret-body-marker" not in str(exc)
            assert "401" in str(exc) or "uth" in str(exc)
            return
    raise AssertionError("expected auth error")


def test_client_sends_session_cookie_when_configured():
    client = WazuhAPIClient(base_url="https://api-kampus", session_cookie="sess-abc")
    assert client._headers()["Cookie"] == "guardins_session=sess-abc"


def test_client_passes_verify_flag_to_requests():
    client = WazuhAPIClient(base_url="https://api-kampus", verify_tls=False)
    resp = MagicMock(status_code=200)
    resp.json.return_value = {"events": [], "total": 0, "limit": 50, "offset": 0}
    with patch.object(client._session, "request", return_value=resp) as req:
        client.fetch_page(limit=50, offset=0)
    assert req.call_args.kwargs["verify"] is False


def test_client_rejects_invalid_verify_env(monkeypatch):
    monkeypatch.setenv("WAZUH_API_VERIFY_TLS", "typo")
    try:
        WazuhAPIClient(base_url="https://api-kampus")
    except ValueError as exc:
        assert "WAZUH_API_VERIFY_TLS" in str(exc)
        return
    raise AssertionError("expected ValueError")


def _ok_page_response(events=(), total=0):
    resp = MagicMock(status_code=200)
    resp.json.return_value = {"events": list(events), "total": total, "limit": 50, "offset": 0}
    resp.cookies = {}
    return resp


def _unauthorized_response():
    resp = MagicMock(status_code=401, text="unauthorized")
    resp.cookies = {}
    return resp


def _login_response(cookie_value="fresh-cookie-123"):
    resp = MagicMock(status_code=200)
    resp.cookies = {"guardins_session": cookie_value}
    resp.json.return_value = {}
    return resp


def test_login_posts_frozen_contract_and_returns_cookie(tmp_path):
    client = WazuhAPIClient(
        base_url="https://api-kampus/api",
        username="svc@kampus",
        password="s3cret",
        session_file=str(tmp_path / "sess.json"),
    )
    with patch.object(client._session, "request", return_value=_login_response()) as req:
        cookie = client.login()
    assert cookie == "fresh-cookie-123"
    body = req.call_args.kwargs["json"]
    assert body == {"email": "svc@kampus", "password": "s3cret"}
    assert "/auth/login" in req.call_args.kwargs["url"]
    assert "s3cret" not in (tmp_path / "sess.json").read_text()


def test_fetch_401_triggers_single_login_and_retries_page(tmp_path):
    client = WazuhAPIClient(
        base_url="https://api-kampus/api",
        username="svc@kampus",
        password="s3cret",
        session_cookie="stale-cookie",
        session_file=str(tmp_path / "sess.json"),
    )
    calls = {"n": 0}

    def fake_request(method, url, **kwargs):
        calls["n"] += 1
        if url.endswith("/auth/login"):
            return _login_response("fresh-cookie-123")
        if calls["n"] == 1:
            return _unauthorized_response()
        return _ok_page_response(total=0)

    with patch.object(client._session, "request", side_effect=fake_request):
        page = client.fetch_page(limit=50, offset=0)
    assert page["total"] == 0
    assert client.session_cookie == "fresh-cookie-123"


def test_fetch_401_after_refresh_raises_fail_fast(tmp_path):
    client = WazuhAPIClient(
        base_url="https://api-kampus/api",
        username="svc@kampus",
        password="s3cret",
        session_file=str(tmp_path / "sess.json"),
    )
    logins = {"n": 0}

    def fake_request(method, url, **kwargs):
        if url.endswith("/auth/login"):
            logins["n"] += 1
            return _login_response("fresh-but-rejected")
        return _unauthorized_response()

    with patch.object(client._session, "request", side_effect=fake_request):
        try:
            client.fetch_page(limit=50, offset=0)
        except Exception as exc:
            assert "401" in str(exc) or "uth" in str(exc)
            assert logins["n"] == 1
            return
    raise AssertionError("expected auth error")


def test_cookie_file_watcher_picks_external_refresh(tmp_path):
    sess = tmp_path / "sess.json"
    sess.write_text('{"cookie": "external-cookie-9"}', encoding="utf-8")
    client = WazuhAPIClient(base_url="https://api-kampus/api", session_file=str(sess))
    assert client._headers()["Cookie"] == "guardins_session=external-cookie-9"
    sess.write_text('{"cookie": "external-cookie-10"}', encoding="utf-8")
    assert client._headers()["Cookie"] == "guardins_session=external-cookie-10"


def test_401_without_login_creds_raises_without_login_attempt(tmp_path):
    client = WazuhAPIClient(
        base_url="https://api-kampus/api",
        session_file=str(tmp_path / "sess.json"),
    )
    with patch.object(
        client._session, "request", return_value=_unauthorized_response()
    ) as req:
        try:
            client.fetch_page(limit=50, offset=0)
        except Exception:
            login_calls = [c for c in req.call_args_list if "/auth/login" in str(c)]
            assert not login_calls
            return
    raise AssertionError("expected auth error")
