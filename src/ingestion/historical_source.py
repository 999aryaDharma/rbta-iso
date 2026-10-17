"""Sumber akuisisi historis dari Wazuh Indexer dengan PIT dan checkpoint."""

import fnmatch
import logging
from typing import Any, Dict, Iterator, List, Optional, Sequence

from src.contracts.raw_alert import CanonicalRawAlert
from src.etl.wazuh_canonicalizer import canonicalize_wazuh_alert
from src.ingestion.checkpoint import CheckpointManager, HistoricalCheckpoint
from src.ingestion.wazuh_client import WazuhIndexerClient

logger = logging.getLogger(__name__)


class WazuhIndexerHistoricalSource:
    """Sumber data historis yang menarik alert dari Wazuh Indexer lewat snapshot PIT harian.

    Parameters
    ----------
    client : WazuhIndexerClient
        Instance client Wazuh Indexer yang sudah terautentikasi.
    checkpoint_manager : CheckpointManager | None
        Pengelola persistensi untuk melanjutkan export yang terputus.
    page_size : int
        Jumlah hit per halaman pencarian (default 500).
    keep_alive : str
        Durasi keep_alive PIT (default '5m').
    """

    def __init__(
        self,
        client: Optional[WazuhIndexerClient] = None,
        checkpoint_manager: Optional[CheckpointManager] = None,
        page_size: int = 500,
        keep_alive: str = "5m",
    ) -> None:
        self.client: WazuhIndexerClient = client or WazuhIndexerClient()
        self.checkpoint_manager: CheckpointManager = checkpoint_manager or CheckpointManager()
        self.page_size: int = page_size
        self.keep_alive: str = keep_alive

    def discover_indices(self, pattern: str = "wazuh-alerts-4.x-*") -> List[str]:
        """Cari dan urutkan index harian yang cocok dengan pola.

        Parameters
        ----------
        pattern : str
            Pola glob untuk mencocokkan index harian.

        Returns
        -------
        List[str]
            Daftar nama index harian, urut naik.
        """
        all_indices = self.client.list_indices(pattern=pattern)
        filtered = [idx for idx in all_indices if fnmatch.fnmatch(idx, pattern)]
        filtered.sort()
        return filtered

    def stream_canonical_alerts(
        self,
        index_pattern: str = "wazuh-alerts-4.x-*",
    ) -> Iterator[CanonicalRawAlert]:
        """Yield CanonicalRawAlert dari index harian yang ditemukan, dengan checkpoint.

        Parameters
        ----------
        index_pattern : str
            Pola pencarian index harian.

        Yields
        ------
        CanonicalRawAlert
            Alert kanonis yang sudah dinormalisasi.
        """
        checkpoint: HistoricalCheckpoint = self.checkpoint_manager.load()
        indices = self.discover_indices(pattern=index_pattern)

        for index_name in indices:
            if index_name in checkpoint.completed_indices:
                logger.info("Skipping already completed index: %s", index_name)
                continue

            logger.info("Starting historical export for index: %s", index_name)
            pit_id = self.client.create_point_in_time(index_name, keep_alive=self.keep_alive)

            # Tentukan cursor search_after awal.
            search_after = None
            if checkpoint.current_index == index_name and checkpoint.last_sort:
                search_after = checkpoint.last_sort
                logger.info("Resuming index '%s' after sort cursor: %s", index_name, search_after)

            try:
                while True:
                    hits = self.client.search_page(
                        pit_id=pit_id,
                        page_size=self.page_size,
                        search_after=search_after,
                        keep_alive=self.keep_alive,
                    )

                    if not hits:
                        # Index sudah habis.
                        checkpoint.mark_index_completed(index_name)
                        self.checkpoint_manager.save(checkpoint)
                        logger.info("Completed historical export for index: %s", index_name)
                        break

                    for hit in hits:
                        canonical_alert = canonicalize_wazuh_alert(hit)
                        yield canonical_alert

                    # Geser cursor ke array sort milik hit terakhir.
                    last_hit = hits[-1]
                    last_sort = last_hit.get("sort")
                    last_id = (
                        last_hit.get("_source", {}).get("id")
                        or last_hit.get("id")
                        or last_hit.get("_id")
                    )

                    if last_sort and last_id:
                        search_after = last_sort
                        checkpoint.current_index = index_name
                        checkpoint.last_sort = list(last_sort)
                        checkpoint.last_wazuh_alert_id = str(last_id)
                        checkpoint.processed_count += len(hits)
                        self.checkpoint_manager.save(checkpoint)

            finally:
                self.client.close_point_in_time(pit_id)
