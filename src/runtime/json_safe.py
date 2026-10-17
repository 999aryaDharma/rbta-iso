"""Helper serialisasi aman-JSON, fingerprint deterministik, dan penyamaran data untuk tampilan."""

from datetime import datetime, date
import hashlib
import json
from pathlib import Path
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, Set, Union
from uuid import UUID

SENSITIVE_KEY_PATTERNS: Set[str] = {
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "api_key",
    "apikey",
    "credential",
    "private_key",
}


def to_json_safe(obj: Any) -> Any:
    """Ubah objek immutable / non-serializable menjadi primitif JSON standar secara rekursif."""
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, UUID):
        return str(obj)
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, (Mapping, MappingProxyType)):
        return {str(k): to_json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_json_safe(item) for item in obj]
    if isinstance(obj, (set, frozenset)):
        try:
            return [to_json_safe(item) for item in sorted(obj)]
        except TypeError:
            return [to_json_safe(item) for item in sorted(str(x) for x in obj)]
    if hasattr(obj, "to_dict") and callable(obj.to_dict):
        return to_json_safe(obj.to_dict())
    if hasattr(obj, "__dict__"):
        return to_json_safe(obj.__dict__)
    return str(obj)


def deterministic_json_dumps(obj: Any) -> str:
    """Hasilkan string JSON yang stabil, ringkas, dan key-nya terurut."""
    safe_obj = to_json_safe(obj)
    return json.dumps(safe_obj, sort_keys=True, separators=(",", ":"))


def compute_canonical_fingerprint(
    wazuh_alert_id: str,
    timestamp: Union[str, datetime],
    agent_id: str,
    agent_name: str,
    rule_id: str,
    rule_level: int,
    rule_group_primary: str,
    srcip: str,
    agent_criticality: float,
    mitre_tactics: Any,
    metadata: Any,
    version: int = 2,
) -> str:
    """Hash bukti kanonis; v2 hanya mengecualikan field envelope transport."""
    if version not in (1, 2):
        raise ValueError("Unsupported canonical fingerprint version")
    if version == 2:
        transport_fields = {
            "source_index", "source_document_id", "source_sort", "fetched_at",
            "source_mode", "timestamp_received", "opensearch_index", "opensearch_document_id",
        }
        if not isinstance(metadata, (Mapping, MappingProxyType)):
            raise TypeError(
                f"canonical fingerprint metadata must be a mapping, got {type(metadata).__name__}"
            )
        metadata = {key: value for key, value in metadata.items() if key not in transport_fields}
    ts_str = timestamp.isoformat() if isinstance(timestamp, datetime) else str(timestamp)
    canonical_dict = {
        "wazuh_alert_id": str(wazuh_alert_id),
        "timestamp": ts_str,
        "agent_id": str(agent_id),
        "agent_name": str(agent_name),
        "rule_id": str(rule_id),
        "rule_level": int(rule_level),
        "rule_group_primary": str(rule_group_primary),
        "srcip": str(srcip) if srcip else "",
        "agent_criticality": float(agent_criticality),
        "mitre_tactics": to_json_safe(mitre_tactics),
        "metadata": to_json_safe(metadata),
    }
    dumped = deterministic_json_dumps(canonical_dict)
    return hashlib.sha256(dumped.encode("utf-8")).hexdigest()


def redact_sensitive_data(obj: Any) -> Any:
    """Samarkan nilai key sensitif untuk tampilan API secara rekursif, struktur tetap dipertahankan."""
    if isinstance(obj, dict):
        redacted = {}
        for k, v in obj.items():
            k_lower = str(k).lower()
            if any(pattern in k_lower for pattern in SENSITIVE_KEY_PATTERNS):
                redacted[k] = "[REDACTED]"
            else:
                redacted[k] = redact_sensitive_data(v)
        return redacted
    if isinstance(obj, list):
        return [redact_sensitive_data(item) for item in obj]
    if isinstance(obj, tuple):
        return tuple(redact_sensitive_data(item) for item in obj)
    return obj
