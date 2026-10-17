"""Order buffer: ruang tunggu pengurut untuk menutup celah urutan antar siklus.

LiveIngestionCoordinator hanya mengurutkan kandidat di dalam satu siklus, sehingga
alert terlambat dari rekonsiliasi (event-time lebih lama, datang di siklus berikutnya)
akan di-ingest setelah alert fast-poll yang lebih baru. OrderBuffer menahan kandidat
yang tepat waktu sebentar lalu melepasnya dengan urutan ``(timestamp, wazuh_alert_id)``.

Aturan pelepasan
----------------
* ``watermark = event-time terbesar yang teramati - hold_window``. Item yang ditahan
  dengan ``timestamp <= watermark`` dilepas secara berurutan.
* Item yang ditahan lebih lama dari ``max_hold`` (wall-clock, ``now - arrived_at``)
  dilepas paksa secara berurutan agar aliran yang sepi tidak membuat buffer macet.
* Alert yang datang lebih tua dari watermark saat ini langsung dilepas dengan penanda
  ``late=True``. Alert itu tetap diproses di hilir — sesuai aturan yang dikunci, tidak ada
  alert valid yang boleh dibuang hanya karena datang tidak berurutan.
* Batas cakupan: ``hold_window`` hanya meratakan jitter yang *lebih kecil* dari window
  (pengurutan ulang antar siklus dalam hitungan detik). Keterlambatan rekonsiliasi dalam
  hitungan menit/jam memang *diperkirakan terlambat*: alert itu langsung diteruskan dengan
  penanda ``late=True`` alih-alih ditahan. Buffer tidak pernah mengklaim menghilangkan
  data terlambat, hanya mengurutkan bagian yang tepat waktu.
* Event-time yang melewati ``now + future_tolerance`` (default 5 menit) dianggap anomali
  jam: langsung diteruskan dengan penanda ``late=True`` dan dihitung di ``future_anomalies``,
  serta tidak pernah menggeser watermark, sehingga satu timestamp buruk tidak bisa membuat
  urutan seluruh aliran macet.
* Kapasitas dibatasi ``max_items``. Bila penuh, kedatangan baru yang tepat waktu ditolak
  (backpressure): ``backpressure_count`` bertambah, ``buffer_dropped`` tetap ``0``, dan
  alert yang ditolak dikembalikan lewat :meth:`pop_refused` agar pemanggil bisa mencoba lagi
  atau langsung meng-ingest-nya. Tidak ada yang dibuang diam-diam. Trade-off: alert yang
  ditolak sengaja *tidak* di-ingest otomatis oleh buffer — pemanggil yang memutuskan
  (coba lagi nanti menjaga urutan, ingest sekarang menjaga kesegaran data). Apa pun
  pilihannya, buffer sendiri tidak membuang apa-apa.

Format checkpoint (desain pemulihan restart; persistensi durable ditunda ke tahap
integrasi, buffer in-memory di sini sengaja tidak menyentuh disk)::

    {
        "max_observed_event_time": "<ISO-8601 str>" | None,
        "buffered": [
            {
                "wazuh_alert_id": str,
                "timestamp": "<ISO-8601 str>",
                "arrived_at": "<ISO-8601 str>",
                "agent_id": str,
                "agent_name": str,
                "rule_group_primary": str,
                "rule_level": int,
                "rule_id": str,
                "mitre_tactics": [str, ...],
                "srcip": str | None,
                "agent_criticality": int,
                "metadata": {JSON-safe mapping},
            },
            ...
        ],
        "late_total": int,
        "backpressure_count": int,
        "future_anomalies": int,
    }

Checkpoint coordinator menyimpan cursor transport Indexer beserta snapshot ini; saat
restart buffer dibangun ulang dengan :meth:`from_checkpoint` sebelum polling dilanjutkan,
sehingga alert yang belum dilepas ditahan lagi, bukan hilang (efek exactly-once tetap
mengandalkan dedup service yang sudah ada).
"""

from bisect import insort
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from src.contracts.raw_alert import CanonicalRawAlert
from src.runtime.json_safe import to_json_safe


@dataclass(frozen=True)
class BufferedRelease:
    """Satu alert yang dilepas buffer beserta penanda keterlambatannya."""

    alert: CanonicalRawAlert
    late: bool = False


def partition_unseen(
    candidates: List[CanonicalRawAlert],
    is_seen_fn: Callable[[str], bool],
) -> Tuple[List[CanonicalRawAlert], List[CanonicalRawAlert]]:
    """Pisahkan kandidat menjadi ``(unseen, seen)`` memakai predikat keanggotaan id.

    Helper murni untuk pra-proses dedup di coordinator: urutan input dipertahankan di kedua
    output, tidak ada yang dibuang, dan predikat dipanggil tepat sekali per kandidat.
    ``is_seen_fn`` menerima ``wazuh_alert_id`` dan mengembalikan True bila sudah diproses.
    """
    unseen: List[CanonicalRawAlert] = []
    seen: List[CanonicalRawAlert] = []
    for alert in candidates:
        (seen if is_seen_fn(alert.wazuh_alert_id) else unseen).append(alert)
    return unseen, seen


class OrderBuffer:
    """Ruang tunggu pengurut terbatas berbasis event-time, dengan jalur langsung untuk alert terlambat."""

    def __init__(
        self,
        hold_window: timedelta = timedelta(seconds=30),
        max_hold: timedelta = timedelta(minutes=5),
        max_items: int = 1000,
        future_tolerance: timedelta = timedelta(minutes=5),
    ) -> None:
        if max_items < 1:
            raise ValueError("max_items must be >= 1")
        self.hold_window: timedelta = hold_window
        self.max_hold: timedelta = max_hold
        self.max_items: int = max_items
        self.future_tolerance: timedelta = future_tolerance
        self._held: List[Tuple[datetime, str, CanonicalRawAlert, datetime]] = []
        self._held_ids: set = set()
        self._max_observed: Optional[datetime] = None
        self._late_total: int = 0
        self._backpressure_count: int = 0
        self._future_anomalies: int = 0
        self._refused: List[CanonicalRawAlert] = []

    def _watermark(self) -> Optional[datetime]:
        if self._max_observed is None:
            return None
        return self._max_observed - self.hold_window

    def add(
        self,
        alerts: List[CanonicalRawAlert],
        now: Optional[datetime] = None,
    ) -> List[BufferedRelease]:
        """Terima kedatangan; kembalikan yang sudah jatuh tempo dengan urutan ``(timestamp, id)``."""
        current = now or datetime.now(timezone.utc)
        released: List[BufferedRelease] = []
        seen_in_call: set = set()
        refused_now: List[CanonicalRawAlert] = []

        for alert in alerts:
            if alert.wazuh_alert_id in seen_in_call or alert.wazuh_alert_id in self._held_ids:
                continue
            seen_in_call.add(alert.wazuh_alert_id)
            if alert.timestamp > current + self.future_tolerance:
                # Anomali jam: diteruskan dengan penanda late, watermark tidak disentuh.
                released.append(BufferedRelease(alert=alert, late=True))
                self._late_total += 1
                self._future_anomalies += 1
                continue
            if self._max_observed is None or alert.timestamp > self._max_observed:
                self._max_observed = alert.timestamp
            watermark = self._watermark()
            assert watermark is not None
            if alert.timestamp <= watermark:
                released.append(BufferedRelease(alert=alert, late=True))
                self._late_total += 1
            elif len(self._held) < self.max_items:
                insort(self._held, (alert.timestamp, alert.wazuh_alert_id, alert, current))
                self._held_ids.add(alert.wazuh_alert_id)
            else:
                refused_now.append(alert)

        if refused_now:
            # Backpressure: ditolak masuk, tidak pernah dibuang. Pemanggil mengambilnya
            # lewat pop_refused() dan wajib mencobanya lagi di siklus berikutnya.
            self._refused.extend(refused_now)
            self._backpressure_count += 1

        watermark = self._watermark()
        if watermark is not None or self._held:
            still_held: List[Tuple[datetime, str, CanonicalRawAlert, datetime]] = []
            for ts, aid, alert, arrived in self._held:
                due_by_watermark = watermark is not None and ts <= watermark
                due_by_max_hold = (current - arrived) >= self.max_hold
                if due_by_watermark or due_by_max_hold:
                    released.append(BufferedRelease(alert=alert, late=False))
                    self._held_ids.discard(aid)
                else:
                    still_held.append((ts, aid, alert, arrived))
            self._held = still_held

        released.sort(key=lambda r: (r.alert.timestamp, r.alert.wazuh_alert_id))
        return released

    def flush(self) -> List[BufferedRelease]:
        """Lepaskan semua yang masih ditahan, dengan urutan ``(timestamp, id)``."""
        released = [BufferedRelease(alert=a, late=False) for _, _, a, _ in self._held]
        self._held = []
        self._held_ids = set()
        return released

    def pop_refused(self) -> List[CanonicalRawAlert]:
        """Ambil kembali alert yang ditolak karena backpressure (pemanggil wajib mencobanya lagi)."""
        refused, self._refused = self._refused, []
        return refused

    def status(self) -> Dict[str, Any]:
        """Counter operasional; ``buffer_dropped`` selalu 0 (tidak pernah membuang)."""
        return {
            "size": len(self._held),
            "late_total": self._late_total,
            "backpressure_count": self._backpressure_count,
            "future_anomalies": self._future_anomalies,
            "buffer_dropped": 0,
            "max_items": self.max_items,
        }

    def to_checkpoint(self) -> Dict[str, Any]:
        """Serialisasi item yang ditahan beserta watermark/counter (lihat docstring modul)."""
        return {
            "max_observed_event_time": (
                self._max_observed.isoformat() if self._max_observed else None
            ),
            "buffered": [
                {
                    "wazuh_alert_id": alert.wazuh_alert_id,
                    "timestamp": alert.timestamp.isoformat(),
                    "arrived_at": arrived.isoformat(),
                    "agent_id": alert.agent_id,
                    "agent_name": alert.agent_name,
                    "rule_group_primary": alert.rule_group_primary,
                    "rule_level": alert.rule_level,
                    "rule_id": alert.rule_id,
                    "mitre_tactics": list(alert.mitre_tactics),
                    "srcip": alert.srcip,
                    "agent_criticality": alert.agent_criticality,
                    "metadata": to_json_safe(dict(alert.metadata)),
                }
                for _, _, alert, arrived in self._held
            ],
            "late_total": self._late_total,
            "backpressure_count": self._backpressure_count,
            "future_anomalies": self._future_anomalies,
        }

    @classmethod
    def from_checkpoint(
        cls,
        snapshot: Dict[str, Any],
        hold_window: timedelta = timedelta(seconds=30),
        max_hold: timedelta = timedelta(minutes=5),
        max_items: int = 1000,
    ) -> "OrderBuffer":
        """Bangun ulang buffer dari output :meth:`to_checkpoint`."""
        buf = cls(hold_window=hold_window, max_hold=max_hold, max_items=max_items)
        raw_max = snapshot.get("max_observed_event_time")
        buf._max_observed = datetime.fromisoformat(raw_max) if raw_max else None
        for entry in snapshot.get("buffered", []):
            alert = CanonicalRawAlert(
                wazuh_alert_id=entry["wazuh_alert_id"],
                timestamp=datetime.fromisoformat(entry["timestamp"]),
                agent_id=entry["agent_id"],
                agent_name=entry["agent_name"],
                rule_group_primary=entry["rule_group_primary"],
                rule_level=entry["rule_level"],
                rule_id=entry["rule_id"],
                mitre_tactics=tuple(entry.get("mitre_tactics", ())),
                srcip=entry.get("srcip"),
                agent_criticality=entry["agent_criticality"],
                metadata=entry.get("metadata", {}),
            )
            arrived = datetime.fromisoformat(entry["arrived_at"])
            insort(buf._held, (alert.timestamp, alert.wazuh_alert_id, alert, arrived))
            buf._held_ids.add(alert.wazuh_alert_id)
        buf._late_total = int(snapshot.get("late_total", 0))
        buf._backpressure_count = int(snapshot.get("backpressure_count", 0))
        buf._future_anomalies = int(snapshot.get("future_anomalies", 0))
        return buf
