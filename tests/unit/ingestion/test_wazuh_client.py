"""Unit test WazuhIndexerClient."""
from unittest.mock import MagicMock, patch
import pytest
import requests

from src.ingestion.wazuh_client import WazuhClientError, WazuhIndexerClient, WazuhAuthError


def test_wazuh_client_init_and_secure_tls_defaults():
    """Client default ke verify_tls=True dan wajib diberi url eksplisit."""
    client = WazuhIndexerClient(
        base_url="https://172.16.83.180:9200",
        username="admin",
        password="secretpassword",
        verify_tls=True,
    )
    assert client.base_url == "https://172.16.83.180:9200"
    assert client.verify_tls is True
    assert client.timeout == (5.0, 30.0)


def test_tls_environment_uses_ca_and_rejects_invalid_boolean(monkeypatch, tmp_path):
    ca = tmp_path / "campus-ca.pem"
    ca.write_text("test certificate placeholder", encoding="utf-8")
    monkeypatch.setenv("WAZUH_INDEXER_CA_PATH", str(ca))
    monkeypatch.setenv("WAZUH_INDEXER_VERIFY_TLS", "true")
    assert WazuhIndexerClient().verify_tls == str(ca)
    monkeypatch.setenv("WAZUH_INDEXER_VERIFY_TLS", "typo")
    with pytest.raises(ValueError, match="WAZUH_INDEXER_VERIFY_TLS"):
        WazuhIndexerClient()


def test_error_does_not_expose_indexer_response_body():
    client = WazuhIndexerClient(base_url="https://wazuh-indexer:9200")
    response = MagicMock(status_code=401, text="sensitive-response-marker")
    with patch.object(client._session, "request", return_value=response):
        with pytest.raises(WazuhAuthError) as error:
            client.list_indices()
    assert "sensitive-response-marker" not in str(error.value)


def test_wazuh_client_401_403_fails_fast_without_retry():
    """Status HTTP 401/403 langsung melempar WazuhAuthError tanpa retry."""
    client = WazuhIndexerClient(base_url="https://wazuh-indexer:9200", username="user", password="bad")

    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_resp.text = "Unauthorized"

    with patch.object(client._session, "request", return_value=mock_resp) as mock_req:
        with pytest.raises(WazuhAuthError, match="Authentication failed"):
            client.create_point_in_time("wazuh-alerts-4.x-2026.04.02")

        assert mock_req.call_count == 1  # tidak ada retry saat 401


def test_wazuh_client_pit_creation_and_close():
    """Client membuat Point-In-Time dan menutupnya dengan benar."""
    client = WazuhIndexerClient(base_url="https://wazuh-indexer:9200")

    # Mock response pembuatan PIT.
    mock_pit_resp = MagicMock()
    mock_pit_resp.status_code = 200
    mock_pit_resp.json.return_value = {"pit_id": "pit_xyz123", "_shards": {"total": 5, "successful": 5, "failed": 0}}

    # Mock response penutupan PIT.
    mock_close_resp = MagicMock()
    mock_close_resp.status_code = 200
    mock_close_resp.json.return_value = {"succeeded": True, "num_freed": 1}

    with patch.object(client._session, "request", side_effect=[mock_pit_resp, mock_close_resp]):
        pit_id = client.create_point_in_time("wazuh-alerts-4.x-2026.04.02")
        assert pit_id == "pit_xyz123"

        closed = client.close_point_in_time(pit_id)
        assert closed is True


def test_wazuh_client_partial_pit_rejected():
    """Bila response PIT berisi shard yang gagal, client melempar WazuhClientError."""
    client = WazuhIndexerClient(base_url="https://wazuh-indexer:9200")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"pit_id": "pit_partial", "_shards": {"total": 5, "successful": 4, "failed": 1}}

    with patch.object(client._session, "request", return_value=mock_resp):
        with pytest.raises(WazuhClientError, match="Partial PIT creation rejected"):
            client.create_point_in_time("wazuh-alerts-4.x-2026.04.02")


def test_wazuh_client_retry_429():
    mock_sleep = MagicMock()
    mock_random = MagicMock(return_value=0.1)
    client = WazuhIndexerClient(base_url="https://wazuh-indexer:9200", sleep_fn=mock_sleep, random_fn=mock_random)

    mock_resp_429 = MagicMock()
    mock_resp_429.status_code = 429

    mock_resp_200 = MagicMock()
    mock_resp_200.status_code = 200
    mock_resp_200.json.return_value = {"pit_id": "pit_success"}

    with patch.object(client._session, "request", side_effect=[mock_resp_429, mock_resp_200]):
        client.create_point_in_time("test")

        assert mock_sleep.call_count == 1
        expected_delay = 0.5 + 0.1 * 0.5 # 2**(1-1)*0.5 + 0.05 = 0.55
        mock_sleep.assert_called_with(expected_delay)


def test_wazuh_client_retry_exhausted():
    mock_sleep = MagicMock()
    client = WazuhIndexerClient(base_url="https://wazuh-indexer:9200", max_retries=3, sleep_fn=mock_sleep)

    mock_resp_502 = MagicMock()
    mock_resp_502.status_code = 502
    mock_resp_502.text = "Bad Gateway"
    mock_resp_502.raise_for_status.side_effect = requests.exceptions.HTTPError("502 Server Error")

    with patch.object(client._session, "request", return_value=mock_resp_502):
        with pytest.raises(WazuhClientError, match="HTTP error"):
            client.create_point_in_time("test")

        assert mock_sleep.call_count == 2


def test_network_failure_includes_host_and_cause():
    client = WazuhIndexerClient(base_url="https://wazuh-indexer:9200")
    with patch.object(
        client._session, "request", side_effect=requests.exceptions.ConnectionError("refused")
    ):
        with pytest.raises(WazuhClientError) as error:
            client.list_indices()
    assert "https://wazuh-indexer:9200" in str(error.value)
    assert error.value.__cause__ is not None
    assert "sensitive" not in str(error.value).lower()


def test_http_error_includes_host_and_cause_without_body():
    client = WazuhIndexerClient(base_url="https://wazuh-indexer:9200")
    mock_resp = MagicMock(status_code=500, text="secret-body-marker")
    mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError("500 Server Error")
    with patch.object(client._session, "request", return_value=mock_resp):
        with pytest.raises(WazuhClientError) as error:
            client.list_indices()
    assert "https://wazuh-indexer:9200" in str(error.value)
    assert "secret-body-marker" not in str(error.value)
    assert error.value.__cause__ is not None


def test_invalid_ca_path_raises_clear_error(monkeypatch, tmp_path):
    monkeypatch.setenv("WAZUH_INDEXER_CA_PATH", str(tmp_path / "missing-ca.pem"))
    monkeypatch.setenv("WAZUH_INDEXER_VERIFY_TLS", "true")
    with pytest.raises(FileNotFoundError, match="WAZUH_INDEXER_CA_PATH"):
        WazuhIndexerClient()
