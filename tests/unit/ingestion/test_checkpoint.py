"""Unit test persistensi HistoricalCheckpoint."""
from pathlib import Path
import pytest
from src.ingestion.checkpoint import HistoricalCheckpoint, CheckpointManager


def test_checkpoint_defaults_and_updates():
    """Checkpoint terinisialisasi dengan default dan memperbarui posisi dengan benar."""
    cp = HistoricalCheckpoint()
    assert cp.mode == "historical"
    assert cp.current_index is None
    assert cp.last_sort is None
    assert cp.processed_count == 0
    assert cp.completed_indices == []

    cp.update(
        index_name="wazuh-alerts-4.x-2026.04.02",
        last_sort=[1775118766650, "1775118766.393"],
        wazuh_alert_id="1775118766.393",
    )
    assert cp.current_index == "wazuh-alerts-4.x-2026.04.02"
    assert cp.last_sort == [1775118766650, "1775118766.393"]
    assert cp.last_wazuh_alert_id == "1775118766.393"
    assert cp.processed_count == 1

    cp.mark_index_completed("wazuh-alerts-4.x-2026.04.02")
    assert "wazuh-alerts-4.x-2026.04.02" in cp.completed_indices
    assert cp.current_index is None
    assert cp.last_sort is None


def test_checkpoint_file_persistence_roundtrip(tmp_path: Path):
    """CheckpointManager menyimpan ke file JSON dan memulihkannya secara identik."""
    cp_file = tmp_path / "checkpoint.json"
    manager = CheckpointManager(cp_file)

    # Load awal tanpa file mengembalikan checkpoint baru.
    cp = manager.load()
    assert cp.processed_count == 0

    cp.update("wazuh-alerts-4.x-2026.04.02", [100, "alert-1"], "alert-1")
    manager.save(cp)

    assert cp_file.exists()

    # Pulihkan dari disk.
    restored = manager.load()
    assert restored.current_index == "wazuh-alerts-4.x-2026.04.02"
    assert restored.last_sort == [100, "alert-1"]
    assert restored.last_wazuh_alert_id == "alert-1"
    assert restored.processed_count == 1


def test_checkpoint_invalid_json_raises_error(tmp_path: Path):
    from src.ingestion.checkpoint import CheckpointError
    cp_file = tmp_path / "bad.json"
    cp_file.write_text("{bad json", encoding="utf-8")

    manager = CheckpointManager(cp_file)
    with pytest.raises(CheckpointError, match="Corrupt checkpoint file"):
        manager.load()

def test_checkpoint_invalid_indices_type_raises_error(tmp_path: Path):
    from src.ingestion.checkpoint import CheckpointError
    import json
    cp_file = tmp_path / "bad2.json"
    cp_file.write_text(json.dumps({"completed_indices": "not a list"}), encoding="utf-8")

    manager = CheckpointManager(cp_file)
    with pytest.raises(CheckpointError, match="Invalid 'completed_indices' type"):
        manager.load()

def test_checkpoint_invalid_processed_count_raises_error(tmp_path: Path):
    from src.ingestion.checkpoint import CheckpointError
    import json
    cp_file = tmp_path / "bad3.json"
    cp_file.write_text(json.dumps({"processed_count": "not an int"}), encoding="utf-8")

    manager = CheckpointManager(cp_file)
    with pytest.raises(CheckpointError, match="Invalid 'processed_count'"):
        manager.load()


@pytest.mark.parametrize(
    "invalid_payload, error_match",
    [
        ({"mode": []}, "Invalid 'mode'"),
        ({"mode": "invalid_mode"}, "Invalid 'mode'"),
        ({"current_index": 123}, "Invalid 'current_index'"),
        ({"last_sort": "not_a_list"}, "Invalid 'last_sort'"),
        ({"processed_count": -1}, "Invalid 'processed_count'"),
        ({"processed_count": True}, "Invalid 'processed_count'"),
        ({"last_wazuh_alert_id": 999}, "Invalid 'last_wazuh_alert_id'"),
        ({"completed_indices": "not_a_list"}, "Invalid 'completed_indices'"),
        ({"completed_indices": [1, 2, 3]}, "Invalid 'completed_indices' item"),
        ({"updated_at": "not_iso_timestamp"}, "Invalid 'updated_at'"),
        ({"updated_at": "2026-08-28T10:00:00"}, "timezone-aware"),
    ],
)
def test_checkpoint_strict_validation_fails_on_corrupt_schema(tmp_path: Path, invalid_payload: dict, error_match: str):
    from src.ingestion.checkpoint import CheckpointError
    import json
    cp_file = tmp_path / "corrupt_schema.json"
    cp_file.write_text(json.dumps(invalid_payload), encoding="utf-8")

    manager = CheckpointManager(cp_file)
    with pytest.raises(CheckpointError, match=error_match):
        manager.load()

