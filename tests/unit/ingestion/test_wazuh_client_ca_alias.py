"""Client indexer harus menerima alias CA_BUNDLE yang dipakai di file .env kampus."""

from src.ingestion.wazuh_client import WazuhIndexerClient


def test_ca_bundle_alias_is_honored(monkeypatch, tmp_path):
    ca = tmp_path / "root-ca.pem"
    ca.write_text("test certificate placeholder", encoding="utf-8")
    monkeypatch.delenv("WAZUH_INDEXER_CA_PATH", raising=False)
    monkeypatch.setenv("WAZUH_INDEXER_CA_BUNDLE", str(ca))
    monkeypatch.setenv("WAZUH_INDEXER_VERIFY_TLS", "true")
    assert WazuhIndexerClient(base_url="https://172.16.83.207:9200").verify_tls == str(ca)


def test_ca_path_wins_over_ca_bundle_alias(monkeypatch, tmp_path):
    ca_path = tmp_path / "a.pem"
    ca_bundle = tmp_path / "b.pem"
    ca_path.write_text("a", encoding="utf-8")
    ca_bundle.write_text("b", encoding="utf-8")
    monkeypatch.setenv("WAZUH_INDEXER_CA_PATH", str(ca_path))
    monkeypatch.setenv("WAZUH_INDEXER_CA_BUNDLE", str(ca_bundle))
    monkeypatch.setenv("WAZUH_INDEXER_VERIFY_TLS", "true")
    assert WazuhIndexerClient(base_url="https://172.16.83.207:9200").verify_tls == str(ca_path)
