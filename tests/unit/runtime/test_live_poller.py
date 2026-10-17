"""Unit test WazuhIndexerLivePoller: fast poll, rekonsiliasi, dan integritas gagal-tertutup."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
import pytest

from src.ingestion.wazuh_client import WazuhIndexerClient
from src.runtime.live_source import (
    LiveCanonicalizationError,
    LiveSourceIntegrityError,
    WazuhIndexerLivePoller,
    derive_daily_indices,
)


def make_hit(idx: int, ts_str: str = "2026-08-28T10:00:00.000+0000") -> dict:
    return {
        "_index": "wazuh-alerts-4.x-2026.08.28",
        "_id": f"doc_{idx}",
        "sort": [1775118765000 + idx, f"alert_{idx}"],
        "_source": {
            "id": f"alert_{idx}",
            "timestamp": ts_str,
            "agent": {"id": "001", "name": "soc-1"},
            "rule": {"id": "5501", "level": 3, "groups": ["pam"]},
            "rule_group_primary": "pam",
            "agent_criticality": 1,
        },
    }


def test_search_allows_missing_daily_indices_but_disallows_partial_results():
    client = MagicMock(spec=WazuhIndexerClient)
    client._request.return_value.json.return_value = {"hits": {"hits": []}}
    poller = WazuhIndexerLivePoller(client=client)
    assert poller.poll_recent(datetime(2026, 9, 28, tzinfo=timezone.utc)) == []
    assert client._request.call_args.kwargs["params"] == {
        "ignore_unavailable": "true", "allow_no_indices": "true",
        "allow_partial_search_results": "false",
    }


@pytest.mark.parametrize("status", [{"timed_out": True}, {"_shards": {"failed": 1}}, {"terminated_early": True}])
def test_partial_search_is_not_a_successful_empty_poll(status):
    client = MagicMock(spec=WazuhIndexerClient)
    client._request.return_value.json.return_value = {**status, "hits": {"hits": []}}
    with pytest.raises(LiveSourceIntegrityError):
        WazuhIndexerLivePoller(client=client).poll_recent()


def test_repeated_full_page_cursor_fails_instead_of_looping():
    client = MagicMock(spec=WazuhIndexerClient)
    page = MagicMock()
    page.json.return_value = {"hits": {"hits": [make_hit(1)]}}
    empty = MagicMock()
    empty.json.return_value = {"hits": {"hits": []}}
    client._request.side_effect = [page, page, empty]
    with pytest.raises(LiveSourceIntegrityError, match="cursor"):
        WazuhIndexerLivePoller(client=client, page_size=1).poll_recent()


def test_derive_daily_indices_midnight_spanning():
    """Index harian yang melewati tengah malam mencakup tepat dua tanggal UTC tanpa wildcard."""
    t_start = datetime(2026, 8, 28, 23, 55, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 8, 29, 0, 5, 0, tzinfo=timezone.utc)

    indices = derive_daily_indices(t_start, t_end)
    assert indices == ["wazuh-alerts-4.x-2026.08.28", "wazuh-alerts-4.x-2026.08.29"]
    assert "wazuh-alerts-*" not in indices


def test_live_poller_bad_document_collected_per_hit_and_valid_continue():
    """Poller per hit: 1 dokumen rusak di tengah halaman dikumpulkan di last_bad_docs;
    dokumen valid di kedua sisinya tetap dikembalikan.
    """
    client = MagicMock(spec=WazuhIndexerClient)
    malformed_hit = {
        "_index": "wazuh-alerts-4.x-2026.08.28",
        "_id": "doc_bad",
        "sort": [1775118765001, "alert_bad"],
        "_source": {
            "id": "alert_bad",
            # timestamp dan agent tidak ada
        },
    }
    client._request.return_value = MagicMock(
        status_code=200,
        json=lambda: {"hits": {"hits": [make_hit(1), malformed_hit, make_hit(2)]}},
    )

    poller = WazuhIndexerLivePoller(client=client)
    alerts = poller.poll_recent(
        current_time=datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    )

    assert [a.wazuh_alert_id for a in alerts] == ["alert_1", "alert_2"]
    assert len(poller.last_bad_docs) == 1
    bad = poller.last_bad_docs[0]
    assert bad["doc_id"] == "doc_bad"
    assert bad["index"] == "wazuh-alerts-4.x-2026.08.28"
    assert bad["error"]


def test_live_poller_last_bad_docs_reset_each_call():
    """last_bad_docs di-reset di setiap pemanggilan paginate (tidak bocor antar pemanggilan)."""
    client = MagicMock(spec=WazuhIndexerClient)
    malformed_hit = {
        "_index": "wazuh-alerts-4.x-2026.08.28",
        "_id": "doc_bad",
        "sort": [1775118765001, "alert_bad"],
        "_source": {"id": "alert_bad"},
    }
    client._request.return_value = MagicMock(
        status_code=200,
        json=lambda: {"hits": {"hits": [malformed_hit]}},
    )
    poller = WazuhIndexerLivePoller(client=client)
    assert poller.poll_recent() == []
    assert len(poller.last_bad_docs) == 1

    client._request.return_value = MagicMock(
        status_code=200,
        json=lambda: {"hits": {"hits": [make_hit(9)]}},
    )
    alerts = poller.poll_recent()
    assert [a.wazuh_alert_id for a in alerts] == ["alert_9"]
    assert poller.last_bad_docs == []


def test_live_poller_malformed_response_empty_dict_fails():
    """Response dict kosong dari Indexer melempar LiveSourceIntegrityError."""
    client = MagicMock(spec=WazuhIndexerClient)
    client._request.return_value = MagicMock(status_code=200, json=lambda: {})

    poller = WazuhIndexerLivePoller(client=client)

    with pytest.raises(LiveSourceIntegrityError, match="missing or invalid 'hits'"):
        poller.poll_recent()


def test_live_poller_malformed_response_hits_not_dict_fails():
    """Response dengan hits: None atau bukan dict melempar LiveSourceIntegrityError."""
    client = MagicMock(spec=WazuhIndexerClient)
    client._request.return_value = MagicMock(status_code=200, json=lambda: {"hits": None})

    poller = WazuhIndexerLivePoller(client=client)

    with pytest.raises(LiveSourceIntegrityError, match="missing or invalid 'hits'"):
        poller.poll_recent()


def test_live_poller_malformed_response_hits_hits_not_list_fails():
    """Response dengan hits.hits yang bukan list melempar LiveSourceIntegrityError."""
    client = MagicMock(spec=WazuhIndexerClient)
    client._request.return_value = MagicMock(status_code=200, json=lambda: {"hits": {"hits": "not-a-list"}})

    poller = WazuhIndexerLivePoller(client=client)

    with pytest.raises(LiveSourceIntegrityError, match="missing or invalid 'hits.hits'"):
        poller.poll_recent()


def test_live_poller_valid_empty_hits_returns_empty_list():
    """Response kosong yang valid mengembalikan list kosong secara normal."""
    client = MagicMock(spec=WazuhIndexerClient)
    client._request.return_value = MagicMock(status_code=200, json=lambda: {"hits": {"hits": []}})

    poller = WazuhIndexerLivePoller(client=client)
    alerts = poller.poll_recent()
    assert alerts == []


def test_live_poller_full_page_missing_sort_cursor_fails():
    """Halaman berisi page_size item tetapi tanpa cursor 'sort' melempar LiveSourceIntegrityError."""
    client = MagicMock(spec=WazuhIndexerClient)
    hit1 = make_hit(1)
    hit2 = make_hit(2)
    del hit2["sort"]  # hapus sort pada hit terakhir halaman penuh

    client._request.return_value = MagicMock(
        status_code=200,
        json=lambda: {"hits": {"hits": [hit1, hit2]}},
    )

    poller = WazuhIndexerLivePoller(client=client, page_size=2)

    with pytest.raises(LiveSourceIntegrityError, match="missing 'sort' field in final hit"):
        poller.poll_recent()


def test_live_poller_full_page_invalid_sort_cursor_fails():
    """Halaman berisi page_size item tetapi cursor 'sort' tidak valid melempar LiveSourceIntegrityError."""
    client = MagicMock(spec=WazuhIndexerClient)
    hit1 = make_hit(1)
    hit2 = make_hit(2)
    hit2["sort"] = "not-a-sequence"

    client._request.return_value = MagicMock(
        status_code=200,
        json=lambda: {"hits": {"hits": [hit1, hit2]}},
    )

    poller = WazuhIndexerLivePoller(client=client, page_size=2)

    with pytest.raises(LiveSourceIntegrityError, match="invalid 'sort' cursor"):
        poller.poll_recent()


def test_live_poller_discover_retained_daily_alert_indices():
    """Poller menyaring dan mengurutkan hanya index alert harian Wazuh yang valid dari daftar Indexer."""
    client = MagicMock(spec=WazuhIndexerClient)
    client.list_indices.return_value = [
        "wazuh-alerts-4.x-2026.08.29",
        ".kibana_1",
        "wazuh-alerts-4.x-2026.08.20",
        "wazuh-monitoring-2026.08.29",
        "wazuh-alerts-4.x-2026.08.25",
        "wazuh-alerts-4.x-invalid-name",
    ]

    poller = WazuhIndexerLivePoller(client=client)
    indices = poller.discover_retained_daily_alert_indices()

    assert indices == [
        "wazuh-alerts-4.x-2026.08.20",
        "wazuh-alerts-4.x-2026.08.25",
        "wazuh-alerts-4.x-2026.08.29",
    ]


def test_live_poller_full_reconciliation_scans_all_retained_indices():
    """Rekonsiliasi seluruh retensi memindai setiap index harian yang ditemukan tanpa batas timestamp."""
    client = MagicMock(spec=WazuhIndexerClient)
    client.list_indices.return_value = [
        "wazuh-alerts-4.x-2026.08.20",
        "wazuh-alerts-4.x-2026.08.29",
    ]
    client._request.return_value = MagicMock(
        status_code=200,
        json=lambda: {"hits": {"hits": [make_hit(100, "2026-08-20T05:00:00.000+0000")]}},
    )

    poller = WazuhIndexerLivePoller(client=client)
    alerts = poller.poll_full_reconciliation()

    assert len(alerts) == 1
    assert alerts[0].wazuh_alert_id == "alert_100"

    args, kwargs = client._request.call_args
    assert args[1] == "/wazuh-alerts-4.x-2026.08.20,wazuh-alerts-4.x-2026.08.29/_search"
    # Query seluruh retensi tidak memakai filter range.
    assert "query" not in kwargs["json_data"]


def test_live_poller_pagination_normal_3_pages():
    """Live poller meminta halaman dengan search_after sampai panjang hasil < page_size."""
    client = MagicMock(spec=WazuhIndexerClient)

    client._request.side_effect = [
        MagicMock(status_code=200, json=lambda: {"hits": {"hits": [make_hit(1), make_hit(2)]}}),
        MagicMock(status_code=200, json=lambda: {"hits": {"hits": [make_hit(3), make_hit(4)]}}),
        MagicMock(status_code=200, json=lambda: {"hits": {"hits": [make_hit(5)]}}),
    ]

    poller = WazuhIndexerLivePoller(client=client, page_size=2)
    alerts = poller.poll_recent(current_time=datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc))
    assert len(alerts) == 5
    assert [a.wazuh_alert_id for a in alerts] == ["alert_1", "alert_2", "alert_3", "alert_4", "alert_5"]
    assert client._request.call_count == 3


def test_live_poller_no_permanent_seen_registry():
    """Poller tidak menelan ID duplikat pada pemanggilan berturut-turut (dedup tugas core)."""
    client = MagicMock(spec=WazuhIndexerClient)
    client._request.side_effect = [
        MagicMock(status_code=200, json=lambda: {"hits": {"hits": [make_hit(1), make_hit(2)]}}),
        MagicMock(status_code=200, json=lambda: {"hits": {"hits": [make_hit(1), make_hit(2), make_hit(3)]}}),
    ]

    poller = WazuhIndexerLivePoller(client=client)
    p1 = poller.poll_recent(current_time=datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc))
    assert len(p1) == 2

    p2 = poller.poll_recent(current_time=datetime(2026, 8, 28, 10, 1, 0, tzinfo=timezone.utc))
    assert len(p2) == 3


def test_live_poller_propagates_transport_error():
    """Live poller tidak menelan exception jaringan diam-diam."""
    client = MagicMock(spec=WazuhIndexerClient)
    client._request.side_effect = Exception("Connection Refused")

    poller = WazuhIndexerLivePoller(client=client)

    with pytest.raises(Exception, match="Connection Refused"):
        poller.poll_recent()


def test_live_poller_cursor_message_includes_offending_value():
    client = MagicMock(spec=WazuhIndexerClient)
    page = MagicMock()
    page.json.return_value = {"hits": {"hits": [make_hit(1)]}}
    empty = MagicMock()
    empty.json.return_value = {"hits": {"hits": []}}
    client._request.side_effect = [page, page, empty]
    with pytest.raises(LiveSourceIntegrityError) as exc_info:
        WazuhIndexerLivePoller(client=client, page_size=1).poll_recent()
    assert "did not advance" in str(exc_info.value)
    assert "1775118765001" in str(exc_info.value)


# Helper integritas poller.

def test_paginate_search_strict_params_when_allow_unavailable_false():
    """allow_unavailable=False mengirim parameter index yang ketat (discovery/rekonsiliasi penuh)."""
    from src.runtime.live_source import WazuhIndexerLivePoller as _P

    client = MagicMock(spec=WazuhIndexerClient)
    client._request.return_value.json.return_value = {"hits": {"hits": []}}
    poller = _P(client=client)
    poller._paginate_search(indices=["wazuh-alerts-4.x-2026.08.28"], allow_unavailable=False)
    assert client._request.call_args.kwargs["params"] == {
        "ignore_unavailable": "false", "allow_no_indices": "false",
        "allow_partial_search_results": "false",
    }


def test_paginate_search_default_stays_tolerant():
    """Default allow_unavailable=True mempertahankan parameter toleran yang lama."""
    client = MagicMock(spec=WazuhIndexerClient)
    client._request.return_value.json.return_value = {"hits": {"hits": []}}
    WazuhIndexerLivePoller(client=client)._paginate_search(
        indices=["wazuh-alerts-4.x-2026.08.28"]
    )
    assert client._request.call_args.kwargs["params"] == {
        "ignore_unavailable": "true", "allow_no_indices": "true",
        "allow_partial_search_results": "false",
    }


def test_validate_index_id_uniqueness_reports_duplicates():
    """Helper smoke test menandai _source.id duplikat tanpa jaringan."""
    from src.runtime.live_source import validate_index_id_uniqueness

    hits = [make_hit(1), make_hit(2)]
    ok = validate_index_id_uniqueness(hits)
    assert ok == {"doc_count": 2, "unique_ids": 2, "id_is_unique": True}

    dup = [make_hit(1), make_hit(1)]
    bad = validate_index_id_uniqueness(dup)
    assert bad == {"doc_count": 2, "unique_ids": 1, "id_is_unique": False}
    assert validate_index_id_uniqueness([]) == {
        "doc_count": 0, "unique_ids": 0, "id_is_unique": True,
    }
