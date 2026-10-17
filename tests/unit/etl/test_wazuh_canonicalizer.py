"""Unit test canonicalizer alert Wazuh."""
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
import pytest

from src.contracts.raw_alert import CanonicalRawAlert
from src.etl.wazuh_canonicalizer import (
    CanonicalizationError,
    canonicalize_wazuh_alert,
    parse_wazuh_timestamp,
)

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "wazuh"


def load_fixture(filename: str) -> dict:
    with open(FIXTURES_DIR / filename, "r", encoding="utf-8") as f:
        return json.load(f)


# Timestamp

def test_parse_wazuh_timestamp_iso_formats():
    """Berbagai timestamp Wazuh timezone-aware yang valid di-parse menjadi UTC."""
    # Dengan offset +0000.
    dt1 = parse_wazuh_timestamp("2026-08-28T05:38:45.712+0000")
    assert dt1.tzinfo is not None
    assert dt1.utcoffset() == timedelta(0)
    assert dt1.year == 2026 and dt1.month == 8 and dt1.day == 28
    assert dt1.hour == 5 and dt1.minute == 38 and dt1.second == 45
    assert dt1.microsecond == 712000

    # Dengan Z.
    dt2 = parse_wazuh_timestamp("2026-08-28T05:38:45.712Z")
    assert dt2.tzinfo is not None
    assert dt2 == dt1

    # Dengan offset eksplisit +08:00 (dikonversi ke UTC).
    dt3 = parse_wazuh_timestamp("2026-08-28T13:38:45.712+08:00")
    assert dt3.tzinfo is not None
    assert dt3 == dt1

    # Objek datetime timezone-aware.
    aware_dt = datetime(2026, 8, 28, 5, 38, 45, 712000, tzinfo=timezone.utc)
    assert parse_wazuh_timestamp(aware_dt) == aware_dt

    # Epoch dalam detik / milidetik.
    dt_epoch = parse_wazuh_timestamp(1787895525.712)
    assert dt_epoch.tzinfo is not None


def test_parse_wazuh_timestamp_rejects_naive():
    """Timestamp naive (string tanpa offset dan objek datetime naive) ditolak tegas."""
    # String ISO naive tanpa offset atau Z.
    with pytest.raises(CanonicalizationError, match="naive|offset"):
        parse_wazuh_timestamp("2026-08-28T05:38:45.712")

    with pytest.raises(CanonicalizationError, match="naive|offset"):
        parse_wazuh_timestamp("2026-08-28 05:38:45")

    # Objek datetime naive.
    naive_dt = datetime(2026, 8, 28, 5, 38, 45)
    with pytest.raises(CanonicalizationError, match="naive|timezone-aware"):
        parse_wazuh_timestamp(naive_dt)


def test_parse_wazuh_timestamp_invalid():
    """Format timestamp tidak valid melempar CanonicalizationError."""
    with pytest.raises(CanonicalizationError, match="[Tt]imestamp|naive"):
        parse_wazuh_timestamp("invalid-date-string")

    with pytest.raises(CanonicalizationError, match="[Tt]imestamp"):
        parse_wazuh_timestamp(None)

    with pytest.raises(CanonicalizationError, match="[Tt]imestamp"):
        parse_wazuh_timestamp("")


# Validasi rule level

def test_canonicalize_rule_level_validation():
    """Validasi ketat rule.level dalam rentang 0..15."""
    base_alert = {
        "id": "1001",
        "timestamp": "2026-08-28T05:00:00Z",
        "rule": {"id": "500", "groups": ["syslog"]},
    }

    # rule.level tidak ada.
    with pytest.raises(CanonicalizationError, match="rule.level"):
        canonicalize_wazuh_alert(base_alert)

    # rule.level null.
    with pytest.raises(CanonicalizationError, match="rule.level"):
        canonicalize_wazuh_alert({**base_alert, "rule": {"id": "500", "level": None, "groups": ["syslog"]}})

    # rule.level bukan angka.
    with pytest.raises(CanonicalizationError, match="rule.level"):
        canonicalize_wazuh_alert({**base_alert, "rule": {"id": "500", "level": "high", "groups": ["syslog"]}})

    # rule.level negatif.
    with pytest.raises(CanonicalizationError, match="Rule level"):
        canonicalize_wazuh_alert({**base_alert, "rule": {"id": "500", "level": -1, "groups": ["syslog"]}})

    # rule.level di luar rentang.
    with pytest.raises(CanonicalizationError, match="Rule level"):
        canonicalize_wazuh_alert({**base_alert, "rule": {"id": "500", "level": 16, "groups": ["syslog"]}})

    # Batas valid 0.
    a0 = canonicalize_wazuh_alert({**base_alert, "rule": {"id": "500", "level": 0, "groups": ["syslog"]}})
    assert a0.rule_level == 0

    # Batas valid 15.
    a15 = canonicalize_wazuh_alert({**base_alert, "rule": {"id": "500", "level": 15, "groups": ["syslog"]}})
    assert a15.rule_level == 15


# Normalisasi agent

def test_canonicalize_agent_null_and_fallback_normalization():
    """Field agent yang null, tidak ada, atau hanya whitespace dinormalisasi menjadi '000' dan 'unknown' tanpa menghasilkan string 'None'."""
    base_alert = {
        "id": "1001",
        "timestamp": "2026-08-28T05:00:00Z",
        "rule": {"id": "500", "level": 3, "groups": ["syslog"]},
    }

    # Blok agent tidak ada.
    a1 = canonicalize_wazuh_alert(base_alert)
    assert a1.agent_id == "000"
    assert a1.agent_name == "unknown"

    # Field agent null.
    a2 = canonicalize_wazuh_alert({**base_alert, "agent": {"id": None, "name": None}})
    assert a2.agent_id == "000"
    assert a2.agent_name == "unknown"
    assert "None" not in (a2.agent_id, a2.agent_name)

    # Field agent kosong/whitespace.
    a3 = canonicalize_wazuh_alert({**base_alert, "agent": {"id": "   ", "name": "   "}})
    assert a3.agent_id == "000"
    assert a3.agent_name == "unknown"

    # Fallback ke nama manager bila nama agent tidak ada.
    a4 = canonicalize_wazuh_alert({
        **base_alert,
        "agent": {"id": "000", "name": None},
        "manager": {"name": "wazuh-soc-master"},
    })
    assert a4.agent_id == "000"
    assert a4.agent_name == "wazuh-soc-master"

    # Agent normal yang valid dipertahankan.
    a5 = canonicalize_wazuh_alert({**base_alert, "agent": {"id": "001", "name": "soc-1"}})
    assert a5.agent_id == "001"
    assert a5.agent_name == "soc-1"


# Dedup MITRE & normalisasi tanpa membedakan huruf besar/kecil

def test_canonicalize_mitre_case_insensitive_deduplication():
    """Taktik MITRE di-dedup tanpa membedakan huruf besar/kecil, penulisan valid pertama dipertahankan."""
    alert_data = {
        "id": "1001",
        "timestamp": "2026-08-28T05:00:00Z",
        "rule": {
            "id": "5501",
            "level": 5,
            "groups": ["pam"],
            "mitre": {
                "tactic": ["Execution", "execution", " EXECUTION "],
            },
            "mitre_tactics": ["defense evasion", "Defense Evasion"],
        },
    }
    alert = canonicalize_wazuh_alert(alert_data)
    assert alert.mitre_tactics == ("Execution", "defense evasion")


# Normalisasi rule group

def test_canonicalize_rule_groups_malformed_normalization():
    """Rule group yang rusak (None, kosong, null, none) disaring dengan aman."""
    base_alert = {
        "id": "1001",
        "timestamp": "2026-08-28T05:00:00Z",
        "rule": {"id": "500", "level": 3},
    }

    # Group tidak ada.
    a1 = canonicalize_wazuh_alert({**base_alert, "rule": {"id": "500", "level": 3}})
    assert a1.rule_group_primary == "unknown"
    assert a1.metadata["rule_groups_all"] == ()

    # List group kosong.
    a2 = canonicalize_wazuh_alert({**base_alert, "rule": {"id": "500", "level": 3, "groups": []}})
    assert a2.rule_group_primary == "unknown"
    assert a2.metadata["rule_groups_all"] == ()

    # List berisi None dan string kosong.
    a3 = canonicalize_wazuh_alert({**base_alert, "rule": {"id": "500", "level": 3, "groups": [None, "", "   "]}})
    assert a3.rule_group_primary == "unknown"
    assert a3.metadata["rule_groups_all"] == ()

    # List berisi literal string 'none', 'null'.
    a4 = canonicalize_wazuh_alert({**base_alert, "rule": {"id": "500", "level": 3, "groups": ["none", "null"]}})
    assert a4.rule_group_primary == "unknown"
    assert a4.metadata["rule_groups_all"] == ()

    # Campuran group valid dengan variasi whitespace dan huruf.
    a5 = canonicalize_wazuh_alert({
        **base_alert,
        "rule": {"id": "500", "level": 3, "groups": [None, " Web ", "web", "syslog"]},
    })
    # 'web' bobotnya lebih tinggi dari 'syslog' (7 vs 3).
    assert a5.rule_group_primary == "web"
    assert a5.metadata["rule_groups_all"] == ("web", "syslog")


# Envelope OpenSearch dan penelusuran

def test_canonicalize_opensearch_hit_envelope_alert_id_traceability():
    """wazuh_alert_id wajib berasal dari _source.id, BUKAN dari _id OpenSearch."""
    hit = {
        "_index": "wazuh-alerts-4.x-2026.08.28",
        "_id": "opensearch-doc-id-xyz",
        "_source": {
            "id": "wazuh-alert-123.456",
            "timestamp": "2026-08-28T05:00:00Z",
            "rule": {"id": "500", "level": 4, "groups": ["syslog"]},
            "agent": {"id": "001", "name": "soc-1"},
        },
        "sort": [1787895526000, "wazuh-alert-123.456"],
    }
    alert = canonicalize_wazuh_alert(hit)
    assert alert.wazuh_alert_id == "wazuh-alert-123.456"
    assert alert.wazuh_alert_id != "opensearch-doc-id-xyz"
    assert alert.metadata["source_document_id"] == "opensearch-doc-id-xyz"
    assert alert.metadata["source_index"] == "wazuh-alerts-4.x-2026.08.28"
    assert alert.metadata["source_sort"] == (1787895526000, "wazuh-alert-123.456")


def test_canonicalize_missing_source_id_fails_fast():
    """Hit OpenSearch tanpa _source.id langsung gagal meski _id ada."""
    hit = {
        "_index": "wazuh-alerts-4.x-2026.08.28",
        "_id": "opensearch-doc-id-xyz",
        "_source": {
            # tidak ada "id"
            "timestamp": "2026-08-28T05:00:00Z",
            "rule": {"id": "500", "level": 4, "groups": ["syslog"]},
        },
    }
    with pytest.raises(CanonicalizationError, match="id"):
        canonicalize_wazuh_alert(hit)


# Fixture & kesetaraan

def test_canonicalize_standard_raw_alert():
    """Kanonisasi fixture alert Wazuh mentah standar."""
    data = load_fixture("raw_alert_standard.json")
    alert = canonicalize_wazuh_alert(data)

    assert isinstance(alert, CanonicalRawAlert)
    assert alert.wazuh_alert_id == "1787895525.48425"
    assert alert.agent_id == "000"
    assert alert.agent_name == "wazuh-soc"
    assert alert.rule_id == "5501"
    assert alert.rule_level == 3
    assert alert.rule_group_primary == "pam"
    assert "Defense Evasion" in alert.mitre_tactics
    assert "Initial Access" in alert.mitre_tactics
    assert alert.agent_criticality == 1
    assert alert.metadata["location"] == "journald"


def test_canonicalize_alert_no_mitre():
    """Kanonisasi alert tanpa bagian MITRE."""
    data = load_fixture("raw_alert_no_mitre.json")
    alert = canonicalize_wazuh_alert(data)

    assert alert.wazuh_alert_id == "1787897412.1001"
    assert alert.agent_name == "pusatkarir"
    assert alert.agent_criticality == 3
    assert alert.rule_group_primary == "syslog"
    assert alert.mitre_tactics == ()
    assert alert.srcip is None


def test_canonicalize_alert_flattened_mitre():
    """Kanonisasi alert dengan taktik MITRE versi datar."""
    data = load_fixture("raw_alert_flattened_mitre.json")
    alert = canonicalize_wazuh_alert(data)

    assert alert.wazuh_alert_id == "1787901330.2002"
    assert alert.agent_name == "dfir-iris"
    assert alert.agent_criticality == 4
    assert alert.rule_group_primary == "sql_injection"
    assert "Initial Access" in alert.mitre_tactics
    assert "Defense Evasion" in alert.mitre_tactics
    assert alert.srcip == "203.0.113.19"


def test_canonicalize_parity_raw_vs_opensearch_hit():
    """Source mentah dan hit OpenSearch dengan _source identik menghasilkan field domain inti yang identik."""
    hit = load_fixture("opensearch_hit.json")
    raw = hit["_source"]

    alert_from_hit = canonicalize_wazuh_alert(hit)
    alert_from_raw = canonicalize_wazuh_alert(raw)

    assert alert_from_hit.wazuh_alert_id == alert_from_raw.wazuh_alert_id
    assert alert_from_hit.timestamp == alert_from_raw.timestamp
    assert alert_from_hit.agent_id == alert_from_raw.agent_id
    assert alert_from_hit.agent_name == alert_from_raw.agent_name
    assert alert_from_hit.rule_group_primary == alert_from_raw.rule_group_primary
    assert alert_from_hit.rule_level == alert_from_raw.rule_level
    assert alert_from_hit.rule_id == alert_from_raw.rule_id
    assert alert_from_hit.mitre_tactics == alert_from_raw.mitre_tactics
    assert alert_from_hit.srcip == alert_from_raw.srcip
    assert alert_from_hit.agent_criticality == alert_from_raw.agent_criticality


def test_canonicalize_missing_mandatory_fields_fails():
    """Field wajib yang tidak ada melempar CanonicalizationError."""
    # ID tidak ada.
    with pytest.raises(CanonicalizationError, match="id"):
        canonicalize_wazuh_alert({
            "timestamp": "2026-08-28T05:00:00Z",
            "rule": {"id": "100", "level": 3, "groups": ["syslog"]},
        })

    # Rule ID tidak ada.
    with pytest.raises(CanonicalizationError, match="rule.id"):
        canonicalize_wazuh_alert({
            "id": "123.456",
            "timestamp": "2026-08-28T05:00:00Z",
            "rule": {"level": 3, "groups": ["syslog"]},
        })

    # Timestamp tidak ada.
    with pytest.raises(CanonicalizationError, match="[Tt]imestamp"):
        canonicalize_wazuh_alert({
            "id": "123.456",
            "rule": {"id": "100", "level": 3, "groups": ["syslog"]},
        })

    # Blok rule tidak ada.
    with pytest.raises(CanonicalizationError, match="rule"):
        canonicalize_wazuh_alert({
            "id": "123.456",
            "timestamp": "2026-08-28T05:00:00Z",
        })


def test_canonicalize_deterministic_output():
    """Kanonisasi berulang pada objek yang sama menghasilkan CanonicalRawAlert yang sama."""
    data = load_fixture("raw_alert_standard.json")
    a1 = canonicalize_wazuh_alert(data)
    a2 = canonicalize_wazuh_alert(data)
    assert a1 == a2
