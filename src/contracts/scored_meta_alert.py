"""Kontrak meta-alert terskor untuk inferensi Isolation Forest dan outbox operasional."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping, Optional

from src.contracts.immutability import freeze_value

VALID_DECISIONS: frozenset[str] = frozenset({
    "CRITICAL",
    "SUSPICIOUS",
    "NOISE_HIGH",
    "NOISE",
    "CONTEXTUAL_ANOMALY",
})

VALID_ACTIONS: frozenset[str] = frozenset({
    "ESCALATE",
    "DAILY_DIGEST",
    "SUPPRESS",
})


@dataclass(frozen=True, slots=True)
class ScoredMetaAlert:
    """Representasi domain immutable dari Meta-Alert yang sudah diskor dan diprioritaskan.

    Attributes
    ----------
    meta_id : int
        ID meta-alert.
    agent_id : str
        ID agent.
    agent_name : str
        Nama host agent.
    rule_group_primary : str
        Rule group primer.
    start_time : datetime
        Timestamp awal (timezone-aware).
    end_time : datetime
        Timestamp akhir (timezone-aware).
    alert_count : int
        Jumlah raw alert yang diagregasi.
    max_severity : int
        Severity rule tertinggi.
    mitre_tactics : tuple[str, ...]
        Taktik MITRE ATT&CK unik.
    seven_features : Mapping[str, float]
        Dict immutable nama fitur -> nilai ternormalisasi untuk 7 fitur kanonis.
    raw_model_score : float
        Skor anomali mentah Isolation Forest (sudah diorientasikan).
    anomaly_score : float
        Skor anomali terkalibrasi yang aman untuk stream (dikalibrasi terhadap reference).
    threshold_used : float
        Threshold Tukey IQR yang dipakai untuk keputusan.
    decision : str
        Kuadran Decision Matrix atau klasifikasi anomali kontekstual.
    action : str
        Rekomendasi tindakan ('ESCALATE', 'DAILY_DIGEST', 'SUPPRESS').
    escalate : bool
        Penanda apakah action bernilai ESCALATE.
    model_version : str
        ID versi artefak model Isolation Forest yang dimuat.
    feature_schema_version : str
        Versi skema fitur.
    score_calibration_version : str
        Versi transformasi kalibrasi skor.
    source_alert_ids : tuple[str, ...]
        Tuple semua ID alert Wazuh anggota, untuk penelusuran.
    metadata : Mapping[str, Any]
        Metadata audit (immutable).
    top_deviations : tuple[tuple[str, float], ...] | None
        Opsional (T11): dua fitur dengan |nilai RobustScaler| terbesar, yaitu (x - median reference)
        / IQR reference (sklearn memakai skala 1 bila IQR = 0). Penjelasan ringan, BUKAN atribusi
        skor Isolation Forest; None untuk record lama.
    """

    meta_id: int
    agent_id: str
    agent_name: str
    rule_group_primary: str
    start_time: datetime
    end_time: datetime
    alert_count: int
    max_severity: int
    mitre_tactics: tuple[str, ...]
    seven_features: Mapping[str, float]
    raw_model_score: float
    anomaly_score: float
    threshold_used: float
    decision: str
    action: str
    escalate: bool
    model_version: str
    feature_schema_version: str
    score_calibration_version: str
    source_alert_ids: tuple[str, ...]
    metadata: Mapping[str, Any] = field(default_factory=dict)
    top_deviations: Optional[tuple[tuple[str, float], ...]] = None

    def __post_init__(self) -> None:
        if self.decision not in VALID_DECISIONS:
            raise ValueError(f"Invalid decision '{self.decision}'. Allowed: {sorted(VALID_DECISIONS)}")

        if self.action not in VALID_ACTIONS:
            raise ValueError(f"Invalid action '{self.action}'. Allowed: {sorted(VALID_ACTIONS)}")

        if not isinstance(self.mitre_tactics, tuple):
            object.__setattr__(self, "mitre_tactics", tuple(self.mitre_tactics))

        if not isinstance(self.source_alert_ids, tuple):
            object.__setattr__(self, "source_alert_ids", tuple(self.source_alert_ids))

        object.__setattr__(self, "seven_features", freeze_value(self.seven_features))
        object.__setattr__(self, "metadata", freeze_value(self.metadata))
        if self.top_deviations is not None:
            object.__setattr__(
                self, "top_deviations", tuple((str(n), float(v)) for n, v in self.top_deviations)
            )
