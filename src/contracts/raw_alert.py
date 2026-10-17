"""Kontrak raw alert kanonis untuk representasi event Wazuh yang sudah dinormalisasi."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping

from src.contracts.immutability import freeze_value


@dataclass(frozen=True, slots=True)
class CanonicalRawAlert:
    """Representasi domain immutable dari raw alert Wazuh SIEM yang sudah dinormalisasi.

    Attributes
    ----------
    wazuh_alert_id : str
        ID alert Wazuh asli (mis. '1787895525.48425').
    timestamp : datetime
        Timestamp event timezone-aware (dinormalisasi ke UTC).
    agent_id : str
        ID agent Wazuh (mis. '001', '000').
    agent_name : str
        Nama host agent Wazuh (mis. 'soc-1', 'pusatkarir').
    rule_group_primary : str
        Rule group primer hasil resolusi.
    rule_level : int
        Level severity rule Wazuh dalam rentang [0, 15].
    rule_id : str
        ID rule Wazuh (mis. '5501').
    mitre_tactics : tuple[str, ...]
        Tuple taktik MITRE ATT&CK unik milik alert ini.
    srcip : str | None
        IP sumber bila ada, None untuk event lokal/HIDS.
    agent_criticality : int
        Skor kritikalitas aset domain dalam rentang [1, 4].
    metadata : Mapping[str, Any]
        Metadata audit dan envelope (immutable).
    """

    wazuh_alert_id: str
    timestamp: datetime
    agent_id: str
    agent_name: str
    rule_group_primary: str
    rule_level: int
    rule_id: str
    mitre_tactics: tuple[str, ...]
    srcip: str | None
    agent_criticality: int
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.wazuh_alert_id or not str(self.wazuh_alert_id).strip():
            raise ValueError("wazuh_alert_id must be a non-empty string")

        if not isinstance(self.timestamp, datetime):
            raise TypeError(f"timestamp must be a datetime instance, got {type(self.timestamp)}")

        if self.timestamp.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware (tzinfo must not be None)")

        if not (0 <= self.rule_level <= 15):
            raise ValueError(f"rule_level must be between 0 and 15, got {self.rule_level}")

        if not (1 <= self.agent_criticality <= 4):
            raise ValueError(f"agent_criticality must be between 1 and 4, got {self.agent_criticality}")

        if not isinstance(self.mitre_tactics, tuple):
            object.__setattr__(self, "mitre_tactics", tuple(self.mitre_tactics))

        object.__setattr__(self, "metadata", freeze_value(self.metadata))
