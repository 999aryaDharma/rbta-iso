from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType
import pytest
import sqlite3
import hashlib

from src.contracts.raw_alert import CanonicalRawAlert
from src.runtime.raw_evidence import RawAlertEvidenceStore, RawEvidenceConflictError
from src.etl.wazuh_canonicalizer import canonicalize_wazuh_alert
from src.runtime.json_safe import deterministic_json_dumps


@pytest.fixture
def store_path(tmp_path: Path) -> Path:
    return tmp_path / "raw_evidence.sqlite3"


@pytest.fixture
def store(store_path: Path) -> RawAlertEvidenceStore:
    return RawAlertEvidenceStore(store_path)


def make_alert(
    alert_id: str = "alert-001",
    agent_id: str = "001",
    rule_id: str = "5710",
    rule_level: int = 5,
    srcip: str = "192.168.1.100",
    metadata: dict | None = None,
    timestamp: datetime | None = None,
) -> CanonicalRawAlert:
    meta = {
        "rule_description": "sshd brute force attempt",
        "location": "/var/log/auth.log",
        "decoder": "sshd",
        "full_log": "Failed password for root from 192.168.1.100 port 22",
        "source_index": "wazuh-alerts-4.x-2026.08.29",
        "source_document_id": "doc-12345",
    }
    if metadata:
        meta.update(metadata)

    return CanonicalRawAlert(
        wazuh_alert_id=alert_id,
        timestamp=timestamp or datetime(2026, 8, 29, 12, 0, 0, tzinfo=timezone.utc),
        agent_id=agent_id,
        agent_name="agent-ubuntu",
        rule_group_primary="authentication_failed",
        rule_level=rule_level,
        rule_id=rule_id,
        mitre_tactics=("credential-access", "initial-access"),
        srcip=srcip,
        agent_criticality=1.0,
        metadata=MappingProxyType(meta),
    )


def test_store_and_retrieve_roundtrip(store: RawAlertEvidenceStore):
    alert = make_alert("wazuh-001")
    inserted = store.store(alert, source_mode="LIVE")
    assert inserted is True

    record = store.get("wazuh-001", redact=False)
    assert record is not None
    assert record["wazuh_alert_id"] == "wazuh-001"
    assert record["rule_id"] == "5710"
    assert record["rule_level"] == 5
    assert record["rule_description"] == "sshd brute force attempt"
    assert record["source_index"] == "wazuh-alerts-4.x-2026.08.29"
    assert record["source_document_id"] == "doc-12345"
    assert "credential-access" in record["mitre_tactics"]


def test_store_idempotent_identical_duplicate(store: RawAlertEvidenceStore):
    alert = make_alert("wazuh-dup")
    assert store.store(alert) is True
    # Menyimpan ulang alert yang persis sama adalah NO-OP yang aman.
    assert store.store(alert) is False
    assert store.count() == 1


@pytest.mark.parametrize("legacy", [False, True])
def test_transport_envelope_does_not_change_evidence_identity(tmp_path, legacy):
    payload = {
        "id": "transport-parity", "timestamp": "2026-09-28T00:00:00Z",
        "agent": {"id": "001", "name": "campus"},
        "rule": {"id": "5501", "level": 3, "groups": ["pam"]},
    }
    hit = {"_source": payload, "_index": "wazuh-alerts-4.x-2026.09.28", "_id": "doc", "sort": [1, "transport-parity"]}
    alert = canonicalize_wazuh_alert(hit)
    path = tmp_path / "evidence.sqlite3"
    store = RawAlertEvidenceStore(path)
    assert store.store(alert)
    store.flush()
    original_hash = store.get(alert.wazuh_alert_id)["canonical_fingerprint"]
    if legacy:
        fields = {name: getattr(alert, name) for name in (
            "wazuh_alert_id", "timestamp", "agent_id", "agent_name", "rule_id", "rule_level",
            "rule_group_primary", "srcip", "agent_criticality", "mitre_tactics", "metadata",
        )}
        fields["srcip"] = fields["srcip"] or ""
        fields["agent_criticality"] = float(fields["agent_criticality"])
        original_hash = hashlib.sha256(deterministic_json_dumps(fields).encode()).hexdigest()
        with sqlite3.connect(path) as conn:
            # Reproduksi database yang dibuat sebelum ada versi fingerprint.
            columns = {row[1] for row in conn.execute("PRAGMA table_info(raw_alert_evidence)")}
            if "fingerprint_version" in columns:
                conn.execute("UPDATE raw_alert_evidence SET fingerprint_version = 1")
            conn.execute("UPDATE raw_alert_evidence SET canonical_fingerprint = ?", (original_hash,))
    reopened = RawAlertEvidenceStore(path)
    assert reopened.store(canonicalize_wazuh_alert(payload)) is False
    assert reopened.get(alert.wazuh_alert_id)["canonical_fingerprint"] == original_hash
    payload["rule"]["level"] = 12
    with pytest.raises(RawEvidenceConflictError):
        reopened.store(canonicalize_wazuh_alert(payload))


def test_store_conflicting_duplicate_raises_error(store: RawAlertEvidenceStore):
    alert1 = make_alert("wazuh-conflict", rule_level=5)
    assert store.store(alert1) is True

    # ID sama tetapi rule_level berbeda -> error konflik.
    alert2 = make_alert("wazuh-conflict", rule_level=12)
    with pytest.raises(RawEvidenceConflictError) as exc_info:
        store.store(alert2)
    assert "Conflicting canonical evidence" in str(exc_info.value)
    assert "wazuh-conflict" in str(exc_info.value)


def test_nested_immutable_metadata_serialization(store: RawAlertEvidenceStore):
    nested_meta = {
        "rule_description": "Nested test",
        "manager": {"name": "wazuh-master"},
        "data": {
            "srcip": "10.0.0.5",
            "tags": ("tag1", "tag2"),
            "sub": {"nested_key": "val"},
        },
        "secret_token": "super_secret_12345",
    }
    alert = make_alert("wazuh-nested", metadata=nested_meta)
    assert store.store(alert) is True

    # Tanpa penyamaran.
    unredacted = store.get("wazuh-nested", redact=False)
    assert unredacted is not None
    assert unredacted["metadata"]["secret_token"] == "super_secret_12345"
    assert unredacted["metadata"]["data"]["tags"] == ["tag1", "tag2"]

    # Tampilan yang disamarkan.
    redacted = store.get("wazuh-nested", redact=True)
    assert redacted is not None
    assert redacted["metadata"]["secret_token"] == "[REDACTED]"
    assert redacted["metadata"]["data"]["srcip"] == "10.0.0.5"


def test_get_meta_alert_raw_alerts_resolution_and_unresolved(store: RawAlertEvidenceStore):
    alert1 = make_alert("aid-1", rule_id="5710", rule_level=5, srcip="10.0.0.1")
    alert2 = make_alert("aid-2", rule_id="5715", rule_level=10, srcip="10.0.0.2")
    store.store(alert1)
    store.store(alert2)

    # ID sumber berisi aid-1, aid-2, dan aid-3 yang hilang.
    source_ids = ["aid-1", "aid-2", "aid-3"]
    res = store.get_meta_alert_raw_alerts(source_ids, meta_id=101, page=1, page_size=10)

    assert res["meta_id"] == 101
    assert res["source_total"] == 3
    assert res["resolved_total"] == 2
    assert res["unresolved_alert_ids"] == ["aid-3"]
    assert res["filtered_total"] == 2
    assert len(res["items"]) == 2
    assert res["items"][0]["wazuh_alert_id"] == "aid-1"
    assert res["items"][1]["wazuh_alert_id"] == "aid-2"


def test_get_meta_alert_raw_alerts_filters_and_search(store: RawAlertEvidenceStore):
    alert1 = make_alert("aid-a", rule_id="5710", rule_level=4, srcip="192.168.1.10", metadata={"rule_description": "SSH login failure"})
    alert2 = make_alert("aid-b", rule_id="5715", rule_level=9, srcip="192.168.1.20", metadata={"rule_description": "SSH root login accepted"})
    store.store(alert1)
    store.store(alert2)

    source_ids = ["aid-a", "aid-b"]

    # Filter berdasarkan level_min.
    res = store.get_meta_alert_raw_alerts(source_ids, level_min=8)
    assert res["source_total"] == 2
    assert res["resolved_total"] == 2
    assert res["filtered_total"] == 1
    assert res["items"][0]["wazuh_alert_id"] == "aid-b"

    # Pencarian multi-field berdasarkan deskripsi.
    res_search = store.get_meta_alert_raw_alerts(source_ids, search="root login")
    assert res_search["filtered_total"] == 1
    assert res_search["items"][0]["wazuh_alert_id"] == "aid-b"


def test_search_multi_field(store: RawAlertEvidenceStore):
    alert1 = make_alert("search-1", rule_id="1001", srcip="172.16.0.1", metadata={"full_log": "Kernel panic detected"})
    alert2 = make_alert("search-2", rule_id="1002", srcip="172.16.0.2", metadata={"rule_description": "Firewall drop event"})
    store.store(alert1)
    store.store(alert2)

    # Pencarian berdasarkan isi full_log.
    found = store.search(query="Kernel panic")
    assert len(found) == 1
    assert found[0]["wazuh_alert_id"] == "search-1"

    # Pencarian berdasarkan IP.
    found_ip = store.search(query="172.16.0.2")
    assert len(found_ip) == 1
    assert found_ip[0]["wazuh_alert_id"] == "search-2"


def test_count_by_hour_valid_and_corrupt_timestamp(store: RawAlertEvidenceStore):
    from src.runtime.raw_evidence import RawEvidenceIntegrityError

    base_t = datetime(2026, 8, 29, 10, 15, 0, tzinfo=timezone.utc)
    alert1 = make_alert("hourly-1", timestamp=base_t)
    alert2 = make_alert("hourly-2", timestamp=base_t + timedelta(minutes=30))
    store.store(alert1)
    store.store(alert2)

    counts = store.count_by_hour(
        start_time=base_t - timedelta(hours=1),
        end_time=base_t + timedelta(hours=1),
    )
    assert counts.get("2026-08-29 10:00") == 2

    # Sisipkan timestamp rusak langsung ke DB untuk menguji integritas gagal-tertutup.
    with store._get_conn() as conn:
        conn.execute(
            "UPDATE raw_alert_evidence SET timestamp = '2026-08-29T10:invalid' WHERE wazuh_alert_id = 'hourly-1'"
        )

    with pytest.raises(RawEvidenceIntegrityError, match="Corrupt timestamp"):
        store.count_by_hour(
            start_time=base_t - timedelta(hours=1),
            end_time=base_t + timedelta(hours=1),
        )


def test_store_decoder_object_from_canonical_metadata(store: RawAlertEvidenceStore):
    """Objek decoder Wazuh harus tersimpan aman lewat metadata immutable."""
    alert = make_alert(
        "wazuh-decoder-object",
        metadata={
            "decoder": {
                "parent": "kernel",
                "name": "kernel",
            }
        },
    )

    inserted = store.store(alert, source_mode="REPLAY")

    assert inserted is True

    record = store.get("wazuh-decoder-object", redact=False)
    assert record is not None

    import json
    assert json.loads(record["decoder"]) == {
        "parent": "kernel",
        "name": "kernel",
    }


def test_replay_duplicate_count_tracks_rows_actually_inserted(store: RawAlertEvidenceStore):
    """Mode replay cepat tidak boleh melaporkan dua baris evidence untuk satu primary key."""
    alert = make_alert("replay-duplicate")

    assert store.store(alert, source_mode="REPLAY", skip_conflict_check=True) is True
    assert store.store(alert, source_mode="REPLAY", skip_conflict_check=True) is False
    assert store.count() == 1


def test_replay_duplicate_keeps_full_canonical_conflict_detection(store: RawAlertEvidenceStore):
    """Optimasi replay tidak boleh melemahkan fingerprint evidence kanonis."""
    original = make_alert("replay-conflict", rule_level=4)
    conflicting = make_alert("replay-conflict", rule_level=12)

    assert store.store(original, source_mode="REPLAY", skip_conflict_check=True) is True
    with pytest.raises(RawEvidenceConflictError, match="Conflicting canonical evidence"):
        store.store(conflicting, source_mode="REPLAY", skip_conflict_check=True)


def test_replay_can_preserve_sanitized_original_envelope(store: RawAlertEvidenceStore):
    """Replay run bisa menyimpan envelope sumber yang persis untuk drill-down audit."""
    alert = make_alert("replay-envelope")
    original = {"id": "replay-envelope", "authorization": "secret", "nested": {"value": 7}}

    assert store.store(alert, original_payload=original, source_mode="REPLAY", skip_conflict_check=True)
    record = store.get("replay-envelope", redact=True)

    assert record is not None
    assert record["original_source_payload"]["authorization"] == "[REDACTED]"
    assert record["original_source_payload"]["nested"] == {"value": 7}


def test_export_canonical_alerts_roundtrips_in_timestamp_order(store: RawAlertEvidenceStore):
    later = make_alert("later", timestamp=datetime(2026, 8, 29, 13, 0, tzinfo=timezone.utc))
    earlier = make_alert("earlier", timestamp=datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc))
    store.store(later)
    store.store(earlier)

    exported = store.export_canonical_alerts()

    assert [alert.wazuh_alert_id for alert in exported] == ["earlier", "later"]
    assert exported[0].rule_group_primary == earlier.rule_group_primary
    assert exported[0].mitre_tactics == earlier.mitre_tactics


def test_canonical_fingerprint_rejects_non_mapping_metadata():
    from src.runtime.json_safe import compute_canonical_fingerprint

    with pytest.raises(TypeError, match="metadata"):
        compute_canonical_fingerprint(
            wazuh_alert_id="a",
            timestamp="t",
            agent_id="1",
            agent_name="n",
            rule_id="r",
            rule_level=1,
            rule_group_primary="g",
            srcip="",
            agent_criticality=1.0,
            mitre_tactics=[],
            metadata=["not-a-mapping"],
        )
