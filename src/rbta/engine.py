"""Engine RBTA single-bucket deterministik dengan ETW lokal per agent."""

from collections import Counter
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

from src.config.domain import has_critical_mitre_tactic
from src.config.research import (
    DEFAULT_BASE_DELTA_T,
    MAX_BUCKET_DURATION,
)
from src.contracts.meta_alert import MetaAlert
from src.contracts.raw_alert import CanonicalRawAlert
from src.rbta.temporal_state import AgentTemporalState


class RBTAInvariantError(ValueError):
    """Dilempar bila invarian internal agregasi RBTA dilanggar."""
    pass


class _ActiveBucket:
    """Akumulator mutable internal untuk window agregasi yang sedang aktif."""

    def __init__(self, alert: CanonicalRawAlert, meta_id: int) -> None:
        self.meta_id: int = meta_id
        self.agent_id: str = alert.agent_id
        self.agent_name: str = alert.agent_name
        self.rule_group_primary: str = alert.rule_group_primary
        self.start_time: datetime = alert.timestamp
        self.end_time: datetime = alert.timestamp
        self.alert_count: int = 1
        self.max_severity: int = alert.rule_level
        self.rule_id_distribution: Counter[str] = Counter({alert.rule_id: 1})
        self.severity_distribution: Counter[int] = Counter({alert.rule_level: 1})
        self.agent_criticality: int = alert.agent_criticality
        self.wazuh_alert_ids: List[str] = [alert.wazuh_alert_id]

        # Dedup MITRE tanpa membedakan huruf besar/kecil, pertahankan bentuk yang pertama ditemukan.
        self.mitre_tactics_order: List[str] = []
        self._mitre_seen: Set[str] = set()
        for t in alert.mitre_tactics:
            k = t.casefold()
            if k not in self._mitre_seen:
                self._mitre_seen.add(k)
                self.mitre_tactics_order.append(t)

        self.critical_mitre_present: bool = has_critical_mitre_tactic(self.mitre_tactics_order)

    def copy(self) -> "_ActiveBucket":
        """Salinan defensif akumulator bucket aktif ini untuk operasi transaksional."""
        copied = _ActiveBucket.__new__(_ActiveBucket)
        copied.meta_id = self.meta_id
        copied.agent_id = self.agent_id
        copied.agent_name = self.agent_name
        copied.rule_group_primary = self.rule_group_primary
        copied.start_time = self.start_time
        copied.end_time = self.end_time
        copied.alert_count = self.alert_count
        copied.max_severity = self.max_severity
        copied.rule_id_distribution = Counter(self.rule_id_distribution)
        copied.severity_distribution = Counter(self.severity_distribution)
        copied.agent_criticality = self.agent_criticality
        copied.wazuh_alert_ids = list(self.wazuh_alert_ids)
        copied.mitre_tactics_order = list(self.mitre_tactics_order)
        copied._mitre_seen = set(self._mitre_seen)
        copied.critical_mitre_present = self.critical_mitre_present
        return copied

    def add(self, alert: CanonicalRawAlert) -> None:
        """Tambahkan alert yang di-merge ke bucket aktif ini."""
        self.alert_count += 1
        if alert.rule_level > self.max_severity:
            self.max_severity = alert.rule_level

        self.rule_id_distribution[alert.rule_id] += 1
        self.severity_distribution[alert.rule_level] += 1

        for t in alert.mitre_tactics:
            k = t.casefold()
            if k not in self._mitre_seen:
                self._mitre_seen.add(k)
                self.mitre_tactics_order.append(t)

        if not self.critical_mitre_present and has_critical_mitre_tactic(alert.mitre_tactics):
            self.critical_mitre_present = True

        self.wazuh_alert_ids.append(alert.wazuh_alert_id)

    def finalize(self) -> MetaAlert:
        """Ubah bucket aktif yang mutable ini menjadi DTO MetaAlert yang immutable."""
        duration = self.end_time - self.start_time
        if duration < timedelta(0):
            raise RBTAInvariantError(
                f"Negative bucket duration detected: start={self.start_time}, end={self.end_time}"
            )
        if duration > MAX_BUCKET_DURATION:
            raise RBTAInvariantError(
                f"Bucket duration {duration} exceeds maximum allowed {MAX_BUCKET_DURATION}"
            )

        return MetaAlert(
            meta_id=self.meta_id,
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            rule_group_primary=self.rule_group_primary,
            start_time=self.start_time,
            end_time=self.end_time,
            alert_count=self.alert_count,
            max_severity=self.max_severity,
            rule_id_distribution=dict(self.rule_id_distribution),
            severity_distribution=dict(self.severity_distribution),
            mitre_tactics_unique=tuple(self.mitre_tactics_order),
            critical_mitre_present=self.critical_mitre_present,
            agent_criticality=self.agent_criticality,
            wazuh_alert_ids=tuple(self.wazuh_alert_ids),
        )


class RBTAEngine:
    """Engine Rule-Based Temporal Aggregation (RBTA) yang deterministik.

    Mengagregasi CanonicalRawAlert yang masuk menjadi bucket MetaAlert immutable
    berdasarkan kunci single-bucket (agent_id, rule_group_primary) dan Elastic Time
    Window adaptif yang lokal per agent.

    Parameters
    ----------
    base_delta_t : timedelta
        Window temporal baseline eksperimen.
    adaptive : bool
        Aktifkan adaptasi EMA lokal per agent setelah warmup (True) atau pertahankan window tetap (False).
    """

    def __init__(
        self,
        base_delta_t: timedelta = DEFAULT_BASE_DELTA_T,
        adaptive: bool = True,
    ) -> None:
        if not isinstance(base_delta_t, timedelta) or base_delta_t.total_seconds() <= 0:
            raise RBTAInvariantError(f"base_delta_t must be a positive timedelta, got {base_delta_t}")

        self._base_delta_t: timedelta = base_delta_t
        self._adaptive: bool = adaptive
        self._temporal_states: Dict[str, AgentTemporalState] = {}
        self._active_buckets: Dict[Tuple[str, str], _ActiveBucket] = {}
        self._seen_alert_ids: Set[str] = set()
        self._new_seen_alert_ids: Set[str] = set()
        self._meta_id_counter: int = 1

    @property
    def seen_alert_count(self) -> int:
        """Jumlah raw alert unik yang sudah di-commit oleh engine."""
        return len(self._seen_alert_ids)

    def has_seen_alert(self, wazuh_alert_id: str) -> bool:
        """True bila raw alert sudah pernah berhasil di-commit."""
        return wazuh_alert_id in self._seen_alert_ids

    def _get_agent_state(self, agent_id: str) -> AgentTemporalState:
        if agent_id not in self._temporal_states:
            self._temporal_states[agent_id] = AgentTemporalState(
                agent_id=agent_id,
                base_delta_t=self._base_delta_t,
                adaptive=self._adaptive,
            )
        return self._temporal_states[agent_id]

    def process(self, alert: CanonicalRawAlert) -> List[MetaAlert]:
        """Proses raw alert kanonis yang masuk lewat agregasi RBTA yang transaksional.

        Atomik saat gagal: bila pemrosesan gagal, tidak ada state internal yang berubah,
        ID alert tidak ditandai seen, dan alert aman untuk dicoba ulang.

        Parameters
        ----------
        alert : CanonicalRawAlert
            Raw alert immutable yang sudah dinormalisasi.

        Returns
        -------
        List[MetaAlert]
            Nol atau lebih MetaAlert final (mis. dari split bucket atau event residual singleton).
        """
        # Idempotensi: ID yang sudah seen berarti alert sudah berhasil di-commit.
        if alert.wazuh_alert_id in self._seen_alert_ids:
            return []

        # Validasi awal terhadap bucket aktif.
        bucket_key = (alert.agent_id, alert.rule_group_primary)
        active_bucket = self._active_buckets.get(bucket_key)

        if active_bucket is not None and alert.agent_criticality != active_bucket.agent_criticality:
            raise RBTAInvariantError(
                f"Contradictory agent_criticality ({alert.agent_criticality} vs "
                f"{active_bucket.agent_criticality}) for agent '{alert.agent_id}'"
            )

        # Evaluasi state kandidat secara transaksional.
        current_agent_state = self._get_agent_state(alert.agent_id)
        candidate_state = current_agent_state.snapshot()
        # Simpan metadata tampilan bersama state temporal per agent supaya bucket yang
        # sudah final/di-drain tidak menghapus nama host di dashboard.
        if alert.agent_name and (candidate_state.agent_name == "unknown" or alert.agent_name != "unknown"):
            candidate_state.agent_name = alert.agent_name
        current_delta_t = candidate_state.observe(alert.timestamp)

        finalized_list: List[MetaAlert] = []
        candidate_meta_id_increment = 0
        candidate_bucket_update: Optional[Tuple[Tuple[str, str], _ActiveBucket]] = None

        if active_bucket is None:
            new_bucket = _ActiveBucket(alert, meta_id=self._meta_id_counter)
            candidate_meta_id_increment = 1
            candidate_bucket_update = (bucket_key, new_bucket)
        else:
            rollback_scalars = (
                active_bucket.start_time,
                active_bucket.end_time,
                active_bucket.alert_count,
                active_bucket.max_severity,
                active_bucket.critical_mitre_present,
                len(active_bucket.wazuh_alert_ids),
                len(active_bucket.mitre_tactics_order),
                list(active_bucket._mitre_seen)
            )

            try:
                # Kasus A: alert datang maju atau di waktu yang sama.
                if alert.timestamp >= active_bucket.end_time:
                    gap = alert.timestamp - active_bucket.end_time
                    prospective_duration = alert.timestamp - active_bucket.start_time

                    if gap <= current_delta_t and prospective_duration <= MAX_BUCKET_DURATION:
                        active_bucket.end_time = alert.timestamp
                        active_bucket.add(alert)
                    else:
                        # Split: finalkan bucket lama, mulai bucket aktif baru.
                        finalized_meta = active_bucket.finalize()
                        new_bucket = _ActiveBucket(alert, meta_id=self._meta_id_counter)
                        candidate_meta_id_increment = 1
                        candidate_bucket_update = (bucket_key, new_bucket)
                        finalized_list.append(finalized_meta)

                # Kasus B: alert datang di dalam window (start <= timestamp < end).
                elif alert.timestamp >= active_bucket.start_time:
                    active_bucket.add(alert)

                # Kasus C: alert residual yang lebih awal (timestamp < start).
                else:
                    boundary_gap = active_bucket.start_time - alert.timestamp
                    prospective_duration = active_bucket.end_time - alert.timestamp

                    if boundary_gap <= current_delta_t and prospective_duration <= MAX_BUCKET_DURATION:
                        active_bucket.start_time = alert.timestamp
                        active_bucket.add(alert)
                    else:
                        # Event yang sangat terlambat dan tidak bisa di-merge -> langsung jadi singleton.
                        singleton = _ActiveBucket(alert, meta_id=self._meta_id_counter)
                        finalized_singleton = singleton.finalize()
                        candidate_meta_id_increment = 1
                        finalized_list.append(finalized_singleton)
                        # Bucket aktif yang ada tidak disentuh.
            except Exception:
                if active_bucket.alert_count > rollback_scalars[2]:
                    active_bucket.rule_id_distribution[alert.rule_id] -= 1
                    if active_bucket.rule_id_distribution[alert.rule_id] == 0:
                        del active_bucket.rule_id_distribution[alert.rule_id]
                    
                    active_bucket.severity_distribution[alert.rule_level] -= 1
                    if active_bucket.severity_distribution[alert.rule_level] == 0:
                        del active_bucket.severity_distribution[alert.rule_level]
                
                (
                    active_bucket.start_time,
                    active_bucket.end_time,
                    active_bucket.alert_count,
                    active_bucket.max_severity,
                    active_bucket.critical_mitre_present,
                    wazuh_len,
                    mitre_len,
                    mitre_seen_list
                ) = rollback_scalars
                
                active_bucket.wazuh_alert_ids = active_bucket.wazuh_alert_ids[:wazuh_len]
                active_bucket.mitre_tactics_order = active_bucket.mitre_tactics_order[:mitre_len]
                active_bucket._mitre_seen = set(mitre_seen_list)
                raise

        # Commit atomik.
        self._temporal_states[alert.agent_id] = candidate_state
        if candidate_bucket_update is not None:
            k, b = candidate_bucket_update
            self._active_buckets[k] = b
        self._meta_id_counter += candidate_meta_id_increment
        self._seen_alert_ids.add(alert.wazuh_alert_id)
        self._new_seen_alert_ids.add(alert.wazuh_alert_id)

        return finalized_list

    def flush_idle(self, event_time: datetime) -> List[MetaAlert]:
        """Finalkan dan kembalikan bucket aktif yang lama idle-nya benar-benar melebihi current_delta_t.

        Parameters
        ----------
        event_time : datetime
            Timestamp event acuan untuk mengecek timeout idle.

        Returns
        -------
        List[MetaAlert]
            Meta-alert final, diurutkan deterministik berdasarkan meta_id.
        """
        if event_time.tzinfo is None:
            raise RBTAInvariantError("event_time must be timezone-aware")

        finalized_list: List[MetaAlert] = []
        keys_to_remove: List[Tuple[str, str]] = []

        for key, bucket in self._active_buckets.items():
            if event_time >= bucket.end_time:
                idle_gap = event_time - bucket.end_time
                agent_state = self._get_agent_state(bucket.agent_id)
                # Pertidaksamaan ketat: saat gap == delta_t, bucket masih boleh di-merge.
                if idle_gap > agent_state.current_delta_t:
                    keys_to_remove.append(key)
                    finalized_list.append(bucket.finalize())

        for key in keys_to_remove:
            del self._active_buckets[key]

        finalized_list.sort(key=lambda m: m.meta_id)
        return finalized_list

    def drain(self) -> List[MetaAlert]:
        """Finalkan dan kembalikan semua bucket aktif yang tersisa.

        Pemanggilan berikutnya pada engine kosong mengembalikan list kosong (idempoten).

        Returns
        -------
        List[MetaAlert]
            Semua meta-alert final, diurutkan deterministik berdasarkan meta_id.
        """
        finalized_list: List[MetaAlert] = []
        for bucket in self._active_buckets.values():
            finalized_list.append(bucket.finalize())

        self._active_buckets.clear()
        finalized_list.sort(key=lambda m: m.meta_id)
        return finalized_list

    def snapshot_agents(self) -> list[dict]:
        """Snapshot read-only state temporal agent untuk dashboard."""
        result = []
        for agent_id, state in self._temporal_states.items():
            agent_buckets = [
                (key, bucket) for key, bucket in self._active_buckets.items()
                if key[0] == agent_id
            ]
            result.append({
                "agent_id": agent_id,
                "agent_name": state.agent_name,
                "event_count": state.warmup_event_count,
                "warmup_required": 100,
                "warmup_progress": min(state.warmup_event_count, 100),
                "is_warmed_up": state.is_warmed_up,
                "baseline_gap_seconds": state.baseline_gap if state.is_warmed_up else None,
                "ema_gap_seconds": state.ema_gap if state.is_warmed_up else None,
                "base_delta_t_seconds": state.base_delta_t.total_seconds(),
                "current_delta_t_seconds": state.current_delta_t.total_seconds(),
                "active_bucket_count": len(agent_buckets),
                "status": "ADAPTIVE" if state.is_warmed_up and state.adaptive else ("WARMUP" if not state.is_warmed_up else "FIXED"),
            })
        return result

    def active_bucket_members(
        self, agent_id: str, rule_group_primary: str
    ) -> Optional[Tuple[int, List[str]]]:
        """Akses read-only untuk drill-down dashboard ke satu bucket yang masih terbuka.

        Mengembalikan ``meta_id`` yang sudah dicadangkan dan daftar ``wazuh_alert_id``
        anggota sesuai urutan datang, atau None bila tidak ada bucket terbuka untuk kunci itu.
        """
        bucket = self._active_buckets.get((agent_id, rule_group_primary))
        if bucket is None:
            return None
        return bucket.meta_id, list(bucket.wazuh_alert_ids)

    def snapshot_buckets(self) -> list[dict]:
        """Snapshot read-only bucket aktif untuk dashboard.

        Bucket aktif masih mengagregasi: ``meta_id``-nya adalah reservasi untuk MetaAlert
        yang akan datang, BUKAN record final. Karena itu ``finalized`` di sini selalu False;
        dashboard tidak boleh menautkan baris ini ke endpoint detail MetaAlert (yang hanya
        membaca finalized_history) sampai bucket ditutup.
        """
        result = []
        for (agent_id, rule_group), bucket in self._active_buckets.items():
            result.append({
                "meta_id": bucket.meta_id,
                "finalized": False,
                "agent_id": agent_id,
                "agent_name": bucket.agent_name,
                "rule_group_primary": rule_group,
                "start_time": bucket.start_time.isoformat(),
                "end_time": bucket.end_time.isoformat(),
                "alert_count": bucket.alert_count,
                "max_severity": bucket.max_severity,
            })
        return result
