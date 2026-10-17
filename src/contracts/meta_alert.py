"""Kontrak meta-alert untuk representasi bucket temporal hasil agregasi."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping

from src.contracts.immutability import freeze_value


@dataclass(frozen=True, slots=True)
class MetaAlert:
    """Representasi domain immutable dari Meta-Alert hasil agregasi RBTA.

    Attributes
    ----------
    meta_id : int
        ID unik meta-alert.
    agent_id : str
        ID agent.
    agent_name : str
        Nama host agent.
    rule_group_primary : str
        Kunci rule group primer dari bucket RBTA.
    start_time : datetime
        Timestamp awal jendela agregasi (timezone-aware).
    end_time : datetime
        Timestamp akhir jendela agregasi (timezone-aware).
    alert_count : int
        Jumlah raw alert yang diagregasi dalam bucket ini (>= 1).
    max_severity : int
        Rule level Wazuh tertinggi dalam bucket ini [0, 15].
    rule_id_distribution : Mapping[str, int]
        Distribusi rule ID ke jumlahnya (immutable).
    severity_distribution : Mapping[int, int]
        Distribusi level severity ke jumlahnya (immutable).
    mitre_tactics_unique : tuple[str, ...]
        Taktik MITRE ATT&CK unik dari seluruh alert dalam bucket.
    critical_mitre_present : bool
        Penanda apakah ada taktik MITRE kritis yang muncul.
    agent_criticality : int
        Skor kritikalitas aset host [1, 4].
    wazuh_alert_ids : tuple[str, ...]
        Tuple semua ID alert Wazuh anggota, untuk penelusuran.
    metadata : Mapping[str, Any]
        Metadata audit (immutable).
    """

    meta_id: int
    agent_id: str
    agent_name: str
    rule_group_primary: str
    start_time: datetime
    end_time: datetime
    alert_count: int
    max_severity: int
    rule_id_distribution: Mapping[str, int]
    severity_distribution: Mapping[int, int]
    mitre_tactics_unique: tuple[str, ...]
    critical_mitre_present: bool
    agent_criticality: int
    wazuh_alert_ids: tuple[str, ...]
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.start_time, datetime) or not isinstance(self.end_time, datetime):
            raise TypeError("start_time and end_time must be datetime instances")

        if self.start_time.tzinfo is None or self.end_time.tzinfo is None:
            raise ValueError("start_time and end_time must be timezone-aware")

        if self.end_time < self.start_time:
            raise ValueError(f"end_time ({self.end_time}) cannot be earlier than start_time ({self.start_time})")

        if self.alert_count < 1:
            raise ValueError(f"alert_count must be at least 1, got {self.alert_count}")

        if not (0 <= self.max_severity <= 15):
            raise ValueError(f"max_severity must be in range [0, 15], got {self.max_severity}")

        if not (1 <= self.agent_criticality <= 4):
            raise ValueError(f"agent_criticality must be in range [1, 4], got {self.agent_criticality}")

        if not isinstance(self.mitre_tactics_unique, tuple):
            object.__setattr__(self, "mitre_tactics_unique", tuple(self.mitre_tactics_unique))

        if not isinstance(self.wazuh_alert_ids, tuple):
            object.__setattr__(self, "wazuh_alert_ids", tuple(self.wazuh_alert_ids))

        object.__setattr__(self, "rule_id_distribution", freeze_value(self.rule_id_distribution))
        object.__setattr__(self, "severity_distribution", freeze_value(self.severity_distribution))
        object.__setattr__(self, "metadata", freeze_value(self.metadata))

    @property
    def duration_sec(self) -> float:
        """Durasi jendela dalam detik."""
        return max(0.0, (self.end_time - self.start_time).total_seconds())
