"""Sumber polling live Wazuh Indexer: polling cepat data terbaru dan scan rekonsiliasi tanpa kehilangan data."""

from datetime import datetime, timedelta, timezone
import logging
import re
from typing import Any, Dict, List, Optional, Sequence, Set

from src.contracts.raw_alert import CanonicalRawAlert
from src.etl.wazuh_canonicalizer import canonicalize_wazuh_alert
from src.ingestion.wazuh_client import WazuhIndexerClient

logger = logging.getLogger(__name__)


def validate_index_id_uniqueness(hits: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Smoke test offline untuk kontrak identitas poller (tanpa jaringan).

    Poller mengasumsikan setiap dokumen sumber punya identitas alert yang unik
    (``_source.id``, fallback ke ``_id``); dedup halaman sukses, cursor ``search_after``,
    dan dedup exactly-once di hilir semuanya bergantung pada asumsi itu. Helper ini
    membuat test dan smoke check bisa memverifikasi asumsi tersebut pada halaman yang
    sudah direkam tanpa menyentuh Indexer.

    Mengembalikan ``{"doc_count", "unique_ids", "id_is_unique"}``. Dokumen tanpa identitas
    yang bisa dipakai tetap dihitung di ``doc_count`` tetapi tidak menyumbang id.
    """
    seen: Set[str] = set()
    count = 0
    for hit in hits:
        count += 1
        doc_id: Any = None
        if isinstance(hit, dict):
            src = hit.get("_source")
            if isinstance(src, dict) and src.get("id") is not None:
                doc_id = src.get("id")
            elif hit.get("_id") is not None:
                doc_id = hit.get("_id")
        if doc_id is not None:
            seen.add(str(doc_id))
    return {
        "doc_count": count,
        "unique_ids": len(seen),
        "id_is_unique": len(seen) == count,
    }


class LiveSourceError(RuntimeError):
    """Exception dasar untuk error sumber live."""
    pass


class LiveSourceIntegrityError(LiveSourceError):
    """Dilempar bila kontrak response, paginasi, atau integritas sumber dilanggar."""
    pass


class LiveCanonicalizationError(LiveSourceIntegrityError):
    """Dilempar bila sebuah dokumen sumber gagal dikanonisasi."""
    pass


def derive_daily_indices(
    start_time: datetime,
    end_time: datetime,
    prefix: str = "wazuh-alerts-4.x-",
) -> List[str]:
    """Turunkan daftar nama index harian untuk semua hari UTC antara start_time dan end_time (inklusif).

    Parameters
    ----------
    start_time : datetime
        Timestamp batas awal.
    end_time : datetime
        Timestamp batas akhir.
    prefix : str
        Prefix index harian Wazuh (default 'wazuh-alerts-4.x-').

    Returns
    -------
    List[str]
        Daftar nama index harian, urut kronologis.
    """
    start_date = start_time.astimezone(timezone.utc).date()
    end_date = end_time.astimezone(timezone.utc).date()
    if start_date > end_date:
        start_date, end_date = end_date, start_date

    indices = []
    curr = start_date
    while curr <= end_date:
        indices.append(f"{prefix}{curr.strftime('%Y.%m.%d')}")
        curr += timedelta(days=1)
    return indices


class WazuhIndexerLivePoller:
    """Polling Wazuh Indexer untuk raw alert keamanan dengan polling cepat dan scan rekonsiliasi.

    Parameters
    ----------
    client : WazuhIndexerClient | None
        Instance client Wazuh.
    overlap_window : timedelta
        Window overlap ke belakang untuk polling terbaru (default 5 menit).
    poll_interval : timedelta
        Jeda antar poll cepat (default 5 detik).
    page_size : int
        Jumlah hit maksimum per request pencarian (default 500).
    """

    def __init__(
        self,
        client: Optional[WazuhIndexerClient] = None,
        overlap_window: timedelta = timedelta(minutes=5),
        poll_interval: timedelta = timedelta(seconds=5),
        page_size: int = 500,
    ) -> None:
        self.client: WazuhIndexerClient = client or WazuhIndexerClient()
        self.overlap_window: timedelta = overlap_window
        self.poll_interval: timedelta = poll_interval
        self.page_size: int = page_size
        # Quarantine per hit: dokumen yang gagal dikanonisasi dikumpulkan di sini (di-reset
        # di setiap pemanggilan _paginate_search) alih-alih menggagalkan satu halaman penuh.
        # Coordinator menguras daftar ini setelah setiap jalur poll, mengarantina setiap entri
        # secara durable, lalu lanjut.
        self.last_bad_docs: List[Dict[str, Any]] = []

    def _paginate_search(
        self,
        indices: Sequence[str],
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        allow_unavailable: bool = True,
    ) -> List[CanonicalRawAlert]:
        """Jalankan pencarian berhalaman yang deterministik dengan @timestamp ASC dan id ASC.

        Validasi response dan integritas kanonisasi dilakukan secara ketat (gagal tertutup).

        Asumsi identitas: setiap hit dikunci oleh id alert yang unik (``_source.id``,
        fallback ``_id``); lihat :func:`validate_index_id_uniqueness` untuk smoke check offline-nya.

        Toleransi shard: response *tanpa* key ``_shards`` diterima selama ``hits.hits``
        berbentuk benar — beberapa fixture Indexer dan proxy menghilangkan ``_shards`` saat
        sukses — tetapi ``failed != 0``, ``timed_out``, atau ``terminated_early`` yang eksplisit
        tetap gagal. ``allow_partial_search_results`` selalu dipaksa ``"false"`` agar cakupan
        shard parsial tidak pernah terlihat seperti sukses.

        ``allow_unavailable=True`` (default, jalur cepat) menoleransi index harian yang tidak ada;
        ``False`` adalah mode ketat untuk pemanggil discovery/rekonsiliasi penuh yang harus
        menyadari index yang hilang.

        Kanonisasi per hit: dokumen yang gagal dikanonisasi ditambahkan ke ``self.last_bad_docs``
        sebagai ``{"index", "doc_id", "error"}`` lalu dilewati — dokumen valid di halaman yang sama
        tetap dikembalikan. ``last_bad_docs`` di-reset setiap pemanggilan.
        """
        self.last_bad_docs = []
        if not indices:
            return []

        target_endpoint = f"/{','.join(indices)}/_search"
        sort_spec = [{"@timestamp": "asc"}, {"id": "asc"}]

        query_range: Dict[str, Any] = {}
        if start_time is not None:
            query_range["gte"] = start_time.isoformat()
        if end_time is not None:
            query_range["lte"] = end_time.isoformat()

        query_body: Dict[str, Any] = {
            "size": self.page_size,
            "sort": sort_spec,
        }
        if query_range:
            query_body["query"] = {"range": {"@timestamp": query_range}}

        new_alerts: List[CanonicalRawAlert] = []
        search_after_cursor = None

        while True:
            current_body = dict(query_body)
            if search_after_cursor is not None:
                current_body["search_after"] = search_after_cursor

            resp = self.client._request("POST", target_endpoint, json_data=current_body, params={
                "ignore_unavailable": "true" if allow_unavailable else "false",
                "allow_no_indices": "true" if allow_unavailable else "false",
                "allow_partial_search_results": "false",
            })
            try:
                data = resp.json()
            except Exception as exc:
                raise LiveSourceIntegrityError(f"Indexer response is not valid JSON: {exc}") from exc

            # Validasi response secara ketat.
            if not isinstance(data, dict):
                raise LiveSourceIntegrityError(
                    f"Malformed Indexer response: expected JSON object, got {type(data).__name__}"
                )
            if data.get("timed_out") or data.get("terminated_early"):
                raise LiveSourceIntegrityError("Incomplete Indexer search response")
            shards = data.get("_shards", {})
            if not isinstance(shards, dict) or shards.get("failed", 0) != 0:
                raise LiveSourceIntegrityError("Invalid or failed Indexer shards")
            if "hits" not in data or not isinstance(data["hits"], dict):
                raise LiveSourceIntegrityError(
                    "Malformed Indexer response: missing or invalid 'hits' dictionary"
                )
            if "hits" not in data["hits"] or not isinstance(data["hits"]["hits"], list):
                raise LiveSourceIntegrityError(
                    "Malformed Indexer response: missing or invalid 'hits.hits' list"
                )

            hits = data["hits"]["hits"]

            # Loop quarantine per hit: kumpulkan dokumen rusak, pertahankan semua dokumen valid di halaman itu.
            for pos, hit in enumerate(hits):
                try:
                    alert = canonicalize_wazuh_alert(hit)
                    new_alerts.append(alert)
                except Exception as exc:
                    doc_id = hit.get("_id") if isinstance(hit, dict) else None
                    idx_name = hit.get("_index") if isinstance(hit, dict) else None
                    logger.warning(
                        "Skipping uncanonicalizable live document "
                        "(index=%s, doc_id=%s, page_pos=%d): %s",
                        idx_name, doc_id, pos, exc,
                    )
                    self.last_bad_docs.append({
                        "index": idx_name,
                        "doc_id": doc_id,
                        "error": (
                            f"Failed to canonicalize document in live source "
                            f"(index={idx_name}, doc_id={doc_id}, page_pos={pos}): {exc}"
                        ),
                    })

            # Kondisi berhenti.
            if len(hits) < self.page_size:
                break

            # Validasi cursor paginasi pada halaman yang penuh.
            last_hit = hits[-1]
            if not isinstance(last_hit, dict) or "sort" not in last_hit:
                raise LiveSourceIntegrityError(
                    f"Full page ({len(hits)} items) missing 'sort' field in final hit for search_after pagination"
                )

            next_cursor = last_hit["sort"]
            if not isinstance(next_cursor, (list, tuple)) or len(next_cursor) != 2:
                raise LiveSourceIntegrityError(
                    "Full page final hit has invalid 'sort' cursor"
                )
            if search_after_cursor is not None:
                try:
                    advancing = tuple(next_cursor) > tuple(search_after_cursor)
                except TypeError:
                    advancing = False
                if not advancing:
                    raise LiveSourceIntegrityError(
                        f"Pagination cursor did not advance (cursor={list(next_cursor)!r})"
                    )
            search_after_cursor = next_cursor

        return new_alerts

    def discover_retained_daily_alert_indices(
        self,
        prefix: str = "wazuh-alerts-4.x-",
    ) -> List[str]:
        """Temukan semua index alert harian Wazuh yang saat ini tersimpan di Indexer.

        Parameters
        ----------
        prefix : str
            Prefix nama index alert harian.

        Returns
        -------
        List[str]
            Daftar nama index alert harian yang ditemukan, urut kronologis.
        """
        raw_indices = self.client.list_indices("wazuh-alerts-*")
        daily_indices: List[str] = []

        date_regex = re.compile(r"^\d{4}\.\d{2}\.\d{2}$")

        for idx_name in raw_indices:
            if not isinstance(idx_name, str):
                continue
            if idx_name.startswith(prefix):
                suffix = idx_name[len(prefix):]
                if date_regex.match(suffix):
                    daily_indices.append(idx_name)
            elif re.match(r"^wazuh-alerts-(?:\d+\.x-)?\d{4}\.\d{2}\.\d{2}$", idx_name):
                daily_indices.append(idx_name)

        return sorted(list(set(daily_indices)))

    def poll_recent(
        self,
        current_time: Optional[datetime] = None,
        recent_poll_cursor: Optional[datetime] = None,
        allow_unavailable: bool = True,
    ) -> List[CanonicalRawAlert]:
        """Jalur polling cepat untuk menemukan alert dengan latensi rendah.

        Parameters
        ----------
        current_time : datetime | None
            Waktu acuan siklus poll (default UTC now).
        recent_poll_cursor : datetime | None
            Hint timestamp awal untuk polling cepat.

        Returns
        -------
        List[CanonicalRawAlert]
            Daftar raw alert yang ditemukan di dalam window polling terbaru.
        """
        now = current_time or datetime.now(timezone.utc)
        start_time = (recent_poll_cursor or now) - self.overlap_window
        indices = derive_daily_indices(start_time, now)
        return self._paginate_search(
            indices=indices, start_time=start_time, end_time=now,
            allow_unavailable=allow_unavailable,
        )

    def poll_reconciliation(
        self,
        current_time: Optional[datetime] = None,
        reconciliation_days: int = 2,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        allow_unavailable: bool = True,
    ) -> List[CanonicalRawAlert]:
        """Jalur scan rekonsiliasi terbaru pada index harian yang tersimpan (default 2 hari: hari ini dan kemarin).

        Parameters
        ----------
        current_time : datetime | None
            Waktu acuan scan.
        reconciliation_days : int
            Jumlah index harian terbaru yang di-scan (default 2: hari ini dan kemarin).
        start_time : datetime | None
            Override waktu mulai (opsional).
        end_time : datetime | None
            Override waktu selesai (opsional).

        Returns
        -------
        List[CanonicalRawAlert]
            Semua alert kanonis yang bisa diambil dari index harian terbaru yang di-scan.
        """
        now = end_time or current_time or datetime.now(timezone.utc)
        scan_start = start_time or (now - timedelta(days=max(0, reconciliation_days - 1)))
        indices = derive_daily_indices(scan_start, now)
        return self._paginate_search(
            indices=indices, start_time=start_time, end_time=end_time,
            allow_unavailable=allow_unavailable,
        )

    def poll_full_reconciliation(
        self,
        prefix: str = "wazuh-alerts-4.x-",
        allow_unavailable: bool = True,
    ) -> List[CanonicalRawAlert]:
        """Scan rekonsiliasi seluruh retensi tanpa kehilangan data di semua index alert harian Wazuh.

        Menemukan setiap index alert harian yang ada di Indexer lalu membaca semuanya sampai habis
        tanpa batas waktu berbasis timestamp.

        Parameters
        ----------
        prefix : str
            Prefix nama index yang dicari.

        Returns
        -------
        List[CanonicalRawAlert]
            Semua alert kanonis yang bisa diambil dari seluruh index harian yang tersimpan.
        """
        indices = self.discover_retained_daily_alert_indices(prefix=prefix)
        if not indices:
            return []
        return self._paginate_search(
            indices=indices, start_time=None, end_time=None,
            allow_unavailable=allow_unavailable,
        )

    def poll_once(
        self,
        current_time: Optional[datetime] = None,
        recent_poll_cursor: Optional[datetime] = None,
        high_watermark: Optional[datetime] = None,
    ) -> List[CanonicalRawAlert]:
        """Shortcut polling cepat (alias high_watermark yang sudah deprecated)."""
        cursor = recent_poll_cursor or high_watermark
        return self.poll_recent(current_time=current_time, recent_poll_cursor=cursor)
