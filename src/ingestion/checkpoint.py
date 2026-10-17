"""Persistensi checkpoint ingestion historis."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, List, Optional, Union


class CheckpointError(RuntimeError):
    """Dilempar bila file checkpoint rusak atau field-nya tidak valid."""
    pass


@dataclass
class HistoricalCheckpoint:
    """State progres ingestion historis lintas index harian.

    Attributes
    ----------
    mode : str
        Mode ingestion ("historical").
    current_index : str | None
        Nama index harian yang sedang diproses.
    last_sort : list[Any] | None
        Array cursor search_after OpenSearch/Wazuh Indexer.
    processed_count : int
        Jumlah raw alert yang sudah diproses/di-yield.
    last_wazuh_alert_id : str | None
        ID alert Wazuh terakhir yang berhasil dikeluarkan.
    completed_indices : list[str]
        Daftar index harian yang sudah habis dibaca.
    updated_at : str
        Timestamp UTC ISO-8601 dari update checkpoint terakhir.
    """

    mode: str = "historical"
    current_index: Optional[str] = None
    last_sort: Optional[List[Any]] = None
    processed_count: int = 0
    last_wazuh_alert_id: Optional[str] = None
    completed_indices: List[str] = field(default_factory=list)
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def update(
        self,
        index_name: str,
        last_sort: List[Any],
        wazuh_alert_id: str,
    ) -> None:
        """Perbarui posisi cursor setelah memproses satu alert atau satu halaman."""
        self.current_index = index_name
        self.last_sort = list(last_sort)
        self.last_wazuh_alert_id = wazuh_alert_id
        self.processed_count += 1
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def mark_index_completed(self, index_name: str) -> None:
        """Tandai index harian selesai dan reset cursor aktif."""
        if index_name not in self.completed_indices:
            self.completed_indices.append(index_name)
        self.current_index = None
        self.last_sort = None
        self.updated_at = datetime.now(timezone.utc).isoformat()


class CheckpointManager:
    """Mengelola serialisasi ke disk dan pemulihan objek HistoricalCheckpoint."""

    def __init__(self, filepath: Union[str, Path] = "checkpoints/historical_checkpoint.json") -> None:
        self.filepath: Path = Path(filepath).resolve()

    def load(self) -> HistoricalCheckpoint:
        """Muat checkpoint dari file JSON, atau kembalikan checkpoint baru bila file belum ada."""
        if not self.filepath.exists():
            return HistoricalCheckpoint()

        try:
            with self.filepath.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise CheckpointError(f"Corrupt checkpoint file '{self.filepath}': {exc}") from exc

        # Validasi tipe field.
        if not isinstance(data, dict):
            raise CheckpointError(f"Checkpoint is not a JSON object: {type(data).__name__}")

        if "mode" in data:
            if not isinstance(data["mode"], str) or data["mode"] != "historical":
                raise CheckpointError(f"Invalid 'mode': expected 'historical', got {data['mode']!r}")

        if "current_index" in data and data["current_index"] is not None:
            if not isinstance(data["current_index"], str):
                raise CheckpointError(f"Invalid 'current_index' type: expected str or None, got {type(data['current_index']).__name__}")

        if "last_sort" in data and data["last_sort"] is not None:
            if not isinstance(data["last_sort"], list) or isinstance(data["last_sort"], (str, bytes)):
                raise CheckpointError(f"Invalid 'last_sort' type: expected list or None, got {type(data['last_sort']).__name__}")

        if "processed_count" in data:
            val = data["processed_count"]
            if isinstance(val, bool) or not isinstance(val, int) or val < 0:
                raise CheckpointError(f"Invalid 'processed_count': expected non-negative int, got {val!r}")

        if "last_wazuh_alert_id" in data and data["last_wazuh_alert_id"] is not None:
            if not isinstance(data["last_wazuh_alert_id"], str):
                raise CheckpointError(f"Invalid 'last_wazuh_alert_id' type: expected str or None, got {type(data['last_wazuh_alert_id']).__name__}")

        if "completed_indices" in data:
            if not isinstance(data["completed_indices"], list):
                raise CheckpointError(f"Invalid 'completed_indices' type: {type(data['completed_indices']).__name__}")
            for idx in data["completed_indices"]:
                if not isinstance(idx, str):
                    raise CheckpointError(f"Invalid 'completed_indices' item: expected str, got {type(idx).__name__}")

        if "updated_at" in data:
            if not isinstance(data["updated_at"], str):
                raise CheckpointError(f"Invalid 'updated_at' type: expected str, got {type(data['updated_at']).__name__}")
            try:
                dt = datetime.fromisoformat(data["updated_at"])
                if dt.tzinfo is None:
                    raise CheckpointError("Invalid 'updated_at': must be timezone-aware ISO-8601 string")
            except Exception as exc:
                if isinstance(exc, CheckpointError):
                    raise
                raise CheckpointError(f"Invalid 'updated_at' ISO timestamp '{data['updated_at']}': {exc}") from exc

        return HistoricalCheckpoint(
            mode=str(data.get("mode", "historical")),
            current_index=data.get("current_index"),
            last_sort=data.get("last_sort"),
            processed_count=int(data.get("processed_count", 0)),
            last_wazuh_alert_id=data.get("last_wazuh_alert_id"),
            completed_indices=list(data.get("completed_indices", [])),
            updated_at=str(data.get("updated_at", datetime.now(timezone.utc).isoformat())),
        )

    def save(self, checkpoint: HistoricalCheckpoint) -> None:
        """Simpan checkpoint ke disk secara atomik lewat file sementara."""
        self.filepath.parent.mkdir(parents=True, exist_ok=True)
        tmp_file = self.filepath.with_suffix(".tmp")

        data = asdict(checkpoint)
        with tmp_file.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        tmp_file.replace(self.filepath)
