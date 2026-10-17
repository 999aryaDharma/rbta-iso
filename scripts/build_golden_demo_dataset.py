#!/usr/bin/env python3
"""Bangun subset demo yang deterministik dan terbatas dari data JSONL Wazuh asli."""

import argparse
from contextlib import contextmanager
import gzip
import hashlib
import heapq
import json
from pathlib import Path
from typing import Iterator, TextIO

from src.etl.wazuh_canonicalizer import canonicalize_wazuh_alert


@contextmanager
def open_text(path: Path, mode: str) -> Iterator[TextIO]:
    if path.name.endswith(".gz"):
        with gzip.open(path, mode, encoding="utf-8") as stream:
            yield stream
    else:
        with path.open(mode, encoding="utf-8") as stream:
            yield stream


def build_golden(source: Path, output: Path, sample_size: int = 10_000, seed: int = 42) -> dict:
    """Pilih hash ber-seed terkecil, lalu tulis dengan urutan event kanonis."""
    if sample_size < 1:
        raise ValueError("sample_size must be positive")
    heap: list[tuple[int, str, str, dict]] = []
    source_digest = hashlib.sha256()
    with source.open("rb") as binary:
        for chunk in iter(lambda: binary.read(1024 * 1024), b""):
            source_digest.update(chunk)

    valid = invalid = 0
    with open_text(source, "rt") as stream:
        for line in stream:
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
                canonical = canonicalize_wazuh_alert(payload)
            except Exception:
                invalid += 1
                continue
            valid += 1
            rank = int.from_bytes(hashlib.sha256(f"{seed}:{canonical.wazuh_alert_id}".encode()).digest()[:8], "big")
            entry = (-rank, canonical.timestamp.isoformat(), canonical.wazuh_alert_id, payload)
            if len(heap) < sample_size:
                heapq.heappush(heap, entry)
            elif entry > heap[0]:
                heapq.heapreplace(heap, entry)

    selected = sorted(heap, key=lambda item: (item[1], item[2]))
    output.parent.mkdir(parents=True, exist_ok=True)
    tmp = output.with_name(output.name + ".tmp")
    writer = gzip.open(tmp, "wt", encoding="utf-8") if output.name.endswith(".gz") else tmp.open("wt", encoding="utf-8")
    with writer as stream:
        for _, _, _, payload in selected:
            stream.write(json.dumps(payload, separators=(",", ":"), ensure_ascii=False) + "\n")
    tmp.replace(output)
    manifest = {
        "classification": "golden",
        "random_seed": seed,
        "description": "Deterministic hash sample of real canonicalizable Wazuh alerts for thesis demonstration",
        "parser_version": "wazuh-canonical-v1",
        "source_sha256": source_digest.hexdigest(),
        "source_valid_events": valid,
        "source_invalid_events": invalid,
        "selected_events": len(selected),
    }
    manifest_path = output.with_name(output.name + ".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path, help="Use .jsonl or .jsonl.gz")
    parser.add_argument("--size", type=int, default=10_000)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    result = build_golden(args.source.resolve(), args.output.resolve(), args.size, args.seed)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
