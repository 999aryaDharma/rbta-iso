"""Katalog provenance (dengan cache) untuk dataset replay yang deterministik."""

from contextlib import contextmanager
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import threading
from typing import Any, Dict, Iterator, List, TextIO, Union

from src.etl.wazuh_canonicalizer import canonicalize_wazuh_alert


SUPPORTED_SUFFIXES = (".jsonl", ".jsonl.gz")


class ReplayDatasetCatalog:
    """Periksa sumber replay sekali lalu pakai ulang metadata provenance yang immutable."""

    def __init__(self, data_dir: Union[str, Path], cache_path: Union[str, Path, None] = None) -> None:
        self.data_dir = Path(data_dir).resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.cache_path = (
            Path(cache_path).resolve()
            if cache_path is not None
            else self.data_dir / ".replay-dataset-catalog.json"
        )
        self._cache_lock = threading.RLock()
        self._cache = self._load_cache()

    def _load_cache(self) -> Dict[str, Any]:
        try:
            payload = json.loads(self.cache_path.read_text(encoding="utf-8"))
            if payload.get("schema_version") == "1.0" and isinstance(payload.get("items"), dict):
                return payload
        except (FileNotFoundError, OSError, ValueError, TypeError):
            pass
        return {"schema_version": "1.0", "items": {}}

    def _save_cache(self) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.cache_path.with_suffix(self.cache_path.suffix + ".tmp")
        tmp_path.write_text(
            json.dumps(self._cache, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        tmp_path.replace(self.cache_path)

    def _paths(self) -> List[Path]:
        return sorted(
            path for path in self.data_dir.iterdir()
            if path.is_file() and self._supported(path.name)
        )

    @staticmethod
    def _supported(name: str) -> bool:
        return name.endswith(SUPPORTED_SUFFIXES)

    def resolve(self, dataset_name: str) -> Path:
        if not dataset_name:
            raise ValueError("Dataset name cannot be empty")
        if Path(dataset_name).name != dataset_name or ".." in dataset_name or "/" in dataset_name or "\\" in dataset_name:
            raise ValueError(f"Path traversal detected in dataset_name: '{dataset_name}'")
        if not self._supported(dataset_name):
            raise ValueError(f"Replay datasets must be .jsonl or .jsonl.gz files, got: '{dataset_name}'")
        path = (self.data_dir / dataset_name).resolve()
        try:
            path.relative_to(self.data_dir)
        except ValueError as exc:
            raise ValueError(f"Dataset path escapes data directory: '{dataset_name}'") from exc
        if not path.is_file():
            raise FileNotFoundError(f"Replay dataset not found: '{dataset_name}'")
        return path

    @contextmanager
    def open_text(self, dataset_name: str) -> Iterator[TextIO]:
        path = self.resolve(dataset_name)
        if path.name.endswith(".gz"):
            with gzip.open(path, "rt", encoding="utf-8") as stream:
                yield stream
        else:
            with path.open("rt", encoding="utf-8") as stream:
                yield stream

    def _source_signature(self, path: Path) -> Dict[str, Any]:
        stat = path.stat()
        explicit_path = path.with_name(path.name + ".manifest.json")
        explicit_stat = explicit_path.stat() if explicit_path.is_file() else None
        return {
            "size_bytes": stat.st_size,
            "mtime_ns": stat.st_mtime_ns,
            "explicit_manifest_size": explicit_stat.st_size if explicit_stat else None,
            "explicit_manifest_mtime_ns": explicit_stat.st_mtime_ns if explicit_stat else None,
        }

    def _explicit_metadata(self, path: Path) -> Dict[str, Any]:
        explicit_path = path.with_name(path.name + ".manifest.json")
        if not explicit_path.is_file():
            return {}
        payload = json.loads(explicit_path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"Dataset manifest must be an object: {explicit_path.name}")
        classification = payload.get("classification", "unclassified")
        if classification not in {"unclassified", "golden", "research"}:
            raise ValueError(f"Invalid dataset classification '{classification}' in {explicit_path.name}")
        allowed = {"classification", "random_seed", "description", "parser_version"}
        return {key: payload[key] for key in allowed if key in payload}

    def _inspect(self, path: Path) -> Dict[str, Any]:
        digest = hashlib.sha256()
        with path.open("rb") as binary_stream:
            for chunk in iter(lambda: binary_stream.read(1024 * 1024), b""):
                digest.update(chunk)

        total = 0
        valid = 0
        invalid = 0
        first_error = None
        timestamp_start = None
        timestamp_end = None
        with self.open_text(path.name) as stream:
            for line_number, raw_line in enumerate(stream, start=1):
                line = raw_line.strip()
                if not line:
                    continue
                total += 1
                try:
                    canonical = canonicalize_wazuh_alert(json.loads(line))
                    timestamp = canonical.timestamp
                    timestamp_start = timestamp if timestamp_start is None or timestamp < timestamp_start else timestamp_start
                    timestamp_end = timestamp if timestamp_end is None or timestamp > timestamp_end else timestamp_end
                    valid += 1
                except Exception as exc:
                    invalid += 1
                    if first_error is None:
                        first_error = {"line_number": line_number, "message": str(exc)}

        metadata = {
            "name": path.name,
            "size_bytes": path.stat().st_size,
            "total_events": total,
            "valid_events": valid,
            "invalid_events": invalid,
            "is_valid": invalid == 0 and valid > 0,
            "first_error": first_error,
            "sha256": digest.hexdigest(),
            "timestamp_start": timestamp_start.isoformat() if timestamp_start else None,
            "timestamp_end": timestamp_end.isoformat() if timestamp_end else None,
            "compression": "gzip" if path.name.endswith(".gz") else "none",
            "classification": "unclassified",
            "inspected_at_utc": datetime.now(timezone.utc).isoformat(),
        }
        metadata.update(self._explicit_metadata(path))
        return metadata

    def get(self, dataset_name: str) -> Dict[str, Any]:
        path = self.resolve(dataset_name)
        signature = self._source_signature(path)
        with self._cache_lock:
            cached = self._cache["items"].get(path.name)
        if cached and cached.get("source_signature") == signature:
            return {**cached["manifest"], "cache_status": "cached", "inspection_status": "cached"}

        manifest = self._inspect(path)
        with self._cache_lock:
            self._cache["items"][path.name] = {
                "source_signature": signature,
                "manifest": manifest,
            }
            self._save_cache()
        return {**manifest, "cache_status": "refreshed", "inspection_status": "cached"}

    def list(self) -> List[Dict[str, Any]]:
        paths = self._paths()
        manifests = [self.get(path.name) for path in paths]
        present = {path.name for path in paths}
        stale = set(self._cache["items"]) - present
        if stale:
            for name in stale:
                self._cache["items"].pop(name, None)
            self._save_cache()
        return manifests

    def list_fast(self) -> List[Dict[str, Any]]:
        """Daftar dataset hanya dari stat/cache; isi alert tidak pernah dibaca."""
        paths = self._paths()
        manifests: List[Dict[str, Any]] = []
        with self._cache_lock:
            for path in paths:
                signature = self._source_signature(path)
                cached = self._cache["items"].get(path.name)
                if cached and cached.get("source_signature") == signature:
                    manifests.append(
                        {**cached["manifest"], "cache_status": "cached", "inspection_status": "cached"}
                    )
                    continue
                manifests.append(
                    {
                        "name": path.name,
                        "size_bytes": path.stat().st_size,
                        "total_events": 0,
                        "valid_events": 0,
                        "invalid_events": 0,
                        "is_valid": False,
                        "first_error": None,
                        "sha256": "",
                        "timestamp_start": None,
                        "timestamp_end": None,
                        "compression": "gzip" if path.name.endswith(".gz") else "none",
                        "classification": "unclassified",
                        "inspected_at_utc": None,
                        "cache_status": "pending",
                        "inspection_status": "pending",
                    }
                )
            present = {path.name for path in paths}
            stale = set(self._cache["items"]) - present
            if stale:
                for name in stale:
                    self._cache["items"].pop(name, None)
                self._save_cache()
        return manifests

    def refresh_all(self, progress_callback=None) -> Dict[str, Any]:
        """Periksa semua dataset saat ini dan lanjut meski ada dataset yang gagal."""
        paths = self._paths()
        failed: List[Dict[str, str]] = []
        completed = 0
        for path in paths:
            error = None
            if progress_callback is not None:
                progress_callback(completed, len(paths), path.name, None)
            try:
                self.get(path.name)
            except Exception as exc:
                error = str(exc)
                failed.append({"name": path.name, "error": error})
            completed += 1
            if progress_callback is not None:
                progress_callback(completed, len(paths), path.name, error)
        return {
            "status": "COMPLETED" if not failed else "ERROR",
            "total_files": len(paths),
            "completed_files": completed,
            "failed_files": len(failed),
            "errors": failed,
        }
