"""Pemuatan deterministik dan provenance untuk korpus Wazuh satu file atau harian."""

from contextlib import contextmanager
from dataclasses import dataclass
import gzip
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterator, List, TextIO, Union

from src.contracts.raw_alert import CanonicalRawAlert
from src.etl.wazuh_canonicalizer import canonicalize_wazuh_alert


SUPPORTED_CORPUS_SUFFIXES = (".jsonl", ".jsonl.gz")


class ResearchCorpusError(RuntimeError):
    """Dilempar bila korpus penelitian tidak bisa dimuat tanpa ambiguitas."""


@dataclass(frozen=True)
class ResearchCorpus:
    alerts: List[CanonicalRawAlert]
    provenance: Dict[str, Any]


def _supported(path: Path) -> bool:
    return path.name.endswith(SUPPORTED_CORPUS_SUFFIXES)


def discover_research_inputs(source: Union[str, Path]) -> List[Path]:
    """Kembalikan input yang didukung dalam urutan leksikal deterministik, tanpa file sidecar."""
    path = Path(source).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"Research input not found: {path}")
    if path.is_file():
        if not _supported(path):
            raise ResearchCorpusError(
                f"Research input must be a .jsonl or .jsonl.gz file, got: {path.name}"
            )
        return [path.resolve()]
    if not path.is_dir():
        raise ResearchCorpusError(f"Research input is neither a file nor directory: {path}")
    files = sorted(
        (item.resolve() for item in path.iterdir() if item.is_file() and _supported(item)),
        key=lambda item: item.name,
    )
    if not files:
        raise ResearchCorpusError(
            f"Research directory '{path}' contains zero supported .jsonl or .jsonl.gz files"
        )
    return files


@contextmanager
def _open_text(path: Path) -> Iterator[TextIO]:
    if path.name.endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8") as stream:
            yield stream
    else:
        with path.open("rt", encoding="utf-8") as stream:
            yield stream


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_research_corpus(source: Union[str, Path]) -> ResearchCorpus:
    """Kanonisasi korpus, tolak ID duplikat, urutkan secara global, dan catat provenance."""
    source_path = Path(source).expanduser()
    files = discover_research_inputs(source_path)
    alerts: List[CanonicalRawAlert] = []
    seen_ids: Dict[str, str] = {}
    file_provenance: List[Dict[str, Any]] = []

    for path in files:
        file_sha = _sha256(path)
        file_count = 0
        with _open_text(path) as stream:
            for line_number, raw_line in enumerate(stream, start=1):
                line = raw_line.strip()
                if not line:
                    continue
                location = f"{path.name}:{line_number}"
                try:
                    alert = canonicalize_wazuh_alert(json.loads(line))
                except Exception as exc:
                    raise ResearchCorpusError(
                        f"Malformed research alert at {location}: {exc}"
                    ) from exc
                first_location = seen_ids.get(alert.wazuh_alert_id)
                if first_location is not None:
                    raise ResearchCorpusError(
                        "Duplicate Wazuh alert id "
                        f"'{alert.wazuh_alert_id}' found at {first_location} and {location}; "
                        "duplicates across temporal partitions would invalidate evaluation"
                    )
                seen_ids[alert.wazuh_alert_id] = location
                alerts.append(alert)
                file_count += 1
        stat = path.stat()
        file_provenance.append(
            {
                "name": path.name,
                "size_bytes": stat.st_size,
                "sha256": file_sha,
                "event_count": file_count,
                "compression": "gzip" if path.name.endswith(".gz") else "none",
            }
        )

    if not alerts:
        raise ResearchCorpusError("Research corpus contains zero canonical alerts")
    alerts.sort(key=lambda alert: (alert.timestamp, alert.wazuh_alert_id))
    combined = hashlib.sha256(
        json.dumps(file_provenance, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    provenance = {
        "source_kind": "directory" if source_path.is_dir() else "file",
        "source_path": str(source_path.resolve()),
        "file_count": len(files),
        "event_count": len(alerts),
        "corpus_sha256": combined,
        "files": file_provenance,
    }
    return ResearchCorpus(alerts=alerts, provenance=provenance)
