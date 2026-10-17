"""Live poller pengganti langsung di atas flat custom API.

Mengimplementasikan antarmuka poller minimal yang dipakai ``LiveIngestionCoordinator``
(``poll_recent`` / ``poll_reconciliation`` / ``poll_full_reconciliation`` / ``poll_once`` +
``last_bad_docs``), sehingga jalur coordinator, worker, order buffer, quarantine, dan
Telegram dipakai ulang tanpa perubahan. Di sini tidak ada index harian: semua jalur
memakai paginasi API perantara ``{events,total,limit,offset}``.
"""

from datetime import datetime
import logging
from typing import Any, Dict, List, Optional

from src.contracts.raw_alert import CanonicalRawAlert
from src.ingestion.wazuh_api_client import WazuhAPIClient

logger = logging.getLogger(__name__)


class WazuhAPILivePoller:
    """Polling API perantara kustom dan mengembalikan alert kanonis."""

    def __init__(
        self,
        client: Optional[WazuhAPIClient] = None,
        page_size: int = 50,
    ) -> None:
        self.client: WazuhAPIClient = client or WazuhAPIClient()
        self.page_size: int = page_size
        self.last_bad_docs: List[Dict[str, Any]] = []

    def _fetch(self) -> List[CanonicalRawAlert]:
        self.last_bad_docs = []
        return self.client.fetch_all_canonical(limit=self.page_size)

    def poll_recent(
        self,
        current_time: Optional[datetime] = None,
        recent_poll_cursor: Optional[datetime] = None,
        **_: Any,
    ) -> List[CanonicalRawAlert]:
        return self._fetch()

    def poll_reconciliation(self, **kwargs: Any) -> List[CanonicalRawAlert]:
        return self._fetch()

    def poll_full_reconciliation(self, **kwargs: Any) -> List[CanonicalRawAlert]:
        return self._fetch()

    def poll_once(self, **kwargs: Any) -> List[CanonicalRawAlert]:
        return self._fetch()
