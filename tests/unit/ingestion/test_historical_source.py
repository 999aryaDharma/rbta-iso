"""Unit dan integration test WazuhIndexerHistoricalSource."""
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock
import pytest

from src.contracts.raw_alert import CanonicalRawAlert
from src.ingestion.checkpoint import CheckpointManager
from src.ingestion.historical_source import WazuhIndexerHistoricalSource
from src.ingestion.wazuh_client import WazuhIndexerClient


def make_hit(idx: int, timestamp_str: str = "2026-04-02T10:00:00.000+0000") -> dict:
    return {
        "_index": "wazuh-alerts-4.x-2026.04.02",
        "_id": f"opensearch_doc_{idx}",
        "sort": [1775118765000 + idx, f"wazuh_alert_{idx}"],
        "_source": {
            "id": f"wazuh_alert_{idx}",
            "timestamp": timestamp_str,
            "agent": {"id": "001", "name": "soc-agent-1"},
            "rule": {"id": "5501", "level": 3, "groups": ["pam", "syslog"]},
            "rule_group_primary": "pam",
            "agent_criticality": 1,
        },
    }


def test_historical_source_discovery_with_missing_dates():
    """Discovery index harian menyaring index sesuai pola, mengurutkan naik, dan menerima tanggal yang bolong."""
    client = MagicMock(spec=WazuhIndexerClient)
    # Index yang tersedia di cluster (mis. 02, 05, 10 Apr; 01 dan 03 Apr tidak ada).
    client.list_indices.return_value = [
        "wazuh-alerts-4.x-2026.04.10",
        "wazuh-alerts-4.x-2026.04.02",
        ".kibana_1",
        "wazuh-alerts-4.x-2026.04.05",
        "wazuh-monitoring-2026.04.02",
    ]

    source = WazuhIndexerHistoricalSource(client=client)
    indices = source.discover_indices(pattern="wazuh-alerts-4.x-*")

    assert indices == [
        "wazuh-alerts-4.x-2026.04.02",
        "wazuh-alerts-4.x-2026.04.05",
        "wazuh-alerts-4.x-2026.04.10",
    ]


def test_historical_source_multipage_retrieval_and_pit_cleanup(tmp_path: Path):
    """Source membaca beberapa halaman 500 hit dengan search_after dan menutup PIT di blok finally."""
    client = MagicMock(spec=WazuhIndexerClient)
    client.list_indices.return_value = ["wazuh-alerts-4.x-2026.04.02"]
    client.create_point_in_time.return_value = "pit_test_session_123"
    client.close_point_in_time.return_value = True

    # Halaman 1: 500 hit, halaman 2: 250 hit, halaman 3: 0 hit (akhir index).
    page1 = [make_hit(i) for i in range(1, 501)]
    page2 = [make_hit(i) for i in range(501, 751)]
    page3 = []

    client.search_page.side_effect = [page1, page2, page3]

    cp_manager = CheckpointManager(tmp_path / "cp.json")
    source = WazuhIndexerHistoricalSource(client=client, checkpoint_manager=cp_manager, page_size=500)

    alerts = list(source.stream_canonical_alerts())

    assert len(alerts) == 750
    assert all(isinstance(a, CanonicalRawAlert) for a in alerts)
    assert alerts[0].wazuh_alert_id == "wazuh_alert_1"
    assert alerts[-1].wazuh_alert_id == "wazuh_alert_750"

    # PIT harus ditutup.
    client.close_point_in_time.assert_called_once_with("pit_test_session_123")

    # Checkpoint menandai index selesai.
    cp = cp_manager.load()
    assert "wazuh-alerts-4.x-2026.04.02" in cp.completed_indices
    assert cp.processed_count == 750


def test_historical_source_resumes_from_checkpoint_without_duplication(tmp_path: Path):
    """Aliran yang terputus dilanjutkan dengan PIT baru dan cursor search_after, tanpa memproses ulang."""
    client = MagicMock(spec=WazuhIndexerClient)
    client.list_indices.return_value = ["wazuh-alerts-4.x-2026.04.02"]
    client.create_point_in_time.return_value = "pit_resumed_456"
    client.close_point_in_time.return_value = True

    # Isi checkpoint seolah berhenti setelah hit ke-500.
    cp_file = tmp_path / "cp.json"
    cp_manager = CheckpointManager(cp_file)
    cp = cp_manager.load()
    cp.update("wazuh-alerts-4.x-2026.04.02", [1775118765500, "wazuh_alert_500"], "wazuh_alert_500")
    cp.processed_count = 500
    cp_manager.save(cp)

    # Halaman sisa saat dilanjutkan.
    remaining_page = [make_hit(i) for i in range(501, 601)]
    client.search_page.side_effect = [remaining_page, []]

    source = WazuhIndexerHistoricalSource(client=client, checkpoint_manager=cp_manager, page_size=500)
    alerts = list(source.stream_canonical_alerts())

    # Hanya 100 alert sisa yang di-yield.
    assert len(alerts) == 100
    assert alerts[0].wazuh_alert_id == "wazuh_alert_501"
    assert alerts[-1].wazuh_alert_id == "wazuh_alert_600"

    # Halaman pencarian dipanggil dengan cursor search_after dari checkpoint.
    first_call_args = client.search_page.call_args_list[0]
    assert first_call_args.kwargs["search_after"] == [1775118765500, "wazuh_alert_500"]

    # Jumlah akhir di checkpoint.
    final_cp = cp_manager.load()
    assert final_cp.processed_count == 600
