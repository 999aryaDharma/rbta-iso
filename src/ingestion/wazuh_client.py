"""Client HTTPS terautentikasi untuk Wazuh Indexer (API kompatibel OpenSearch)."""

import logging
import os
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
import requests
from requests.auth import HTTPBasicAuth

logger = logging.getLogger(__name__)


class WazuhClientError(RuntimeError):
    """Error dasar untuk operasi client Wazuh Indexer."""
    pass


class WazuhAuthError(WazuhClientError):
    """Dilempar bila autentikasi (401/403) ke Wazuh Indexer gagal."""
    pass


class WazuhIndexerClient:
    """Client aman untuk berkomunikasi dengan Wazuh Indexer lewat REST API OpenSearch.

    Parameters
    ----------
    base_url : str
        Base URL Wazuh Indexer (mis. "https://172.16.83.180:9200").
    username : str | None
        Username HTTP Basic Auth (default dari env WAZUH_INDEXER_USERNAME).
    password : str | None
        Password HTTP Basic Auth (default dari env WAZUH_INDEXER_PASSWORD).
    verify_tls : bool | str
        Pengaturan verifikasi SSL: True (default), False, atau path CA bundle.
    timeout : Tuple[float, float]
        (connect_timeout, read_timeout) dalam detik.
    max_retries : int
        Batas retry saat error jaringan sementara/5xx.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_tls: Optional[Union[bool, str]] = None,
        timeout: Tuple[float, float] = (5.0, 30.0),
        max_retries: int = 3,
        sleep_fn=None,
        random_fn=None,
    ) -> None:
        self.base_url: str = (base_url or os.getenv("WAZUH_INDEXER_URL", "https://localhost:9200")).rstrip("/")
        self.username: Optional[str] = username or os.getenv("WAZUH_INDEXER_USERNAME")
        self.password: Optional[str] = password or os.getenv("WAZUH_INDEXER_PASSWORD")
        if verify_tls is None:
            tls_setting = os.getenv("WAZUH_INDEXER_VERIFY_TLS", "true").strip().lower()
            if tls_setting not in ("true", "false"):
                raise ValueError("WAZUH_INDEXER_VERIFY_TLS must be true or false")
            if tls_setting == "true":
                ca_path = os.getenv("WAZUH_INDEXER_CA_PATH") or os.getenv("WAZUH_INDEXER_CA_BUNDLE")
                if ca_path:
                    from pathlib import Path as _Path

                    if not _Path(ca_path).is_file():
                        raise FileNotFoundError(
                            f"WAZUH_INDEXER_CA_PATH points to missing file: {ca_path}"
                        )
                    verify_tls = ca_path
                else:
                    verify_tls = True
            else:
                verify_tls = False
        self.verify_tls: Union[bool, str] = verify_tls
        self.timeout: Tuple[float, float] = timeout
        self.max_retries: int = max_retries

        self._sleep_fn = sleep_fn or time.sleep
        self._random_fn = random_fn or (lambda: __import__('random').random())

        self._session = requests.Session()
        if self.username and self.password:
            self._session.auth = HTTPBasicAuth(self.username, self.password)

    def _request(
        self,
        method: str,
        endpoint: str,
        json_data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> requests.Response:
        """Jalankan request terautentikasi dengan retry untuk error sementara; 401/403 langsung gagal."""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        headers = {"Content-Type": "application/json"}

        for attempt in range(1, self.max_retries + 1):
            try:
                resp = self._session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    json=json_data,
                    params=params,
                    verify=self.verify_tls,
                    timeout=self.timeout,
                )

                # 401 / 403 langsung gagal.
                if resp.status_code in (401, 403):
                    raise WazuhAuthError(
                        f"Authentication failed ({resp.status_code}) against Wazuh Indexer at {self.base_url}"
                    )

                # Error server sementara (429, 502, 503, 504) -> retry.
                if resp.status_code in (429, 502, 503, 504) and attempt < self.max_retries:
                    delay = min(30.0, (2 ** (attempt - 1)) * 0.5) + self._random_fn() * 0.5
                    self._sleep_fn(delay)
                    continue

                resp.raise_for_status()
                return resp

            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
                if attempt >= self.max_retries:
                    raise WazuhClientError(
                        f"Network failure calling Wazuh Indexer at {self.base_url} after {self.max_retries} attempts"
                    ) from exc
                delay = min(30.0, (2 ** (attempt - 1)) * 0.5) + self._random_fn() * 0.5
                self._sleep_fn(delay)
            except WazuhAuthError:
                raise
            except requests.exceptions.HTTPError as exc:
                raise WazuhClientError(
                    f"HTTP error ({resp.status_code}) calling Wazuh Indexer at {self.base_url}"
                ) from exc

        raise WazuhClientError("Exceeded max retries calling Wazuh Indexer")

    def list_indices(self, pattern: str = "wazuh-alerts-*") -> List[str]:
        """Daftar nama index cluster yang cocok dengan pola.

        Parameters
        ----------
        pattern : str
            Wildcard pola index (mis. 'wazuh-alerts-*').

        Returns
        -------
        List[str]
            Daftar nama index yang cocok.
        """
        resp = self._request("GET", f"/_cat/indices/{pattern}", params={"format": "json"})
        indices_data = resp.json()
        return [str(item["index"]) for item in indices_data if "index" in item]

    def create_point_in_time(self, index_name: str, keep_alive: str = "5m") -> str:
        """Buka snapshot Point-In-Time (PIT) pada satu index harian.

        Parameters
        ----------
        index_name : str
            Nama index harian tujuan.
        keep_alive : str
            Durasi retensi PIT (mis. '5m').

        Returns
        -------
        str
            ID Point-In-Time yang unik.

        Raises
        ------
        WazuhClientError
            Bila pembuatan PIT gagal atau ada kegagalan sebagian shard.
        """
        resp = self._request("POST", f"/{index_name}/_search/point_in_time", params={"keep_alive": keep_alive})
        data = resp.json()

        shards = data.get("_shards", {})
        if shards.get("failed", 0) > 0:
            raise WazuhClientError(
                f"Partial PIT creation rejected for index '{index_name}': {shards.get('failed')} shards failed out of {shards.get('total')}"
            )

        pit_id = data.get("pit_id")
        if not pit_id:
            raise WazuhClientError(f"No pit_id returned in response for index '{index_name}'")

        return str(pit_id)

    def close_point_in_time(self, pit_id: str) -> bool:
        """Tutup konteks snapshot Point-In-Time yang aktif.

        Parameters
        ----------
        pit_id : str
            ID Point-In-Time yang akan ditutup.

        Returns
        -------
        bool
            True bila penutupan berhasil.
        """
        try:
            resp = self._request("DELETE", "/_search/point_in_time", json_data={"pit_id": [pit_id]})
            data = resp.json()
            return bool(data.get("succeeded", True))
        except Exception as exc:
            logger.warning("Error closing PIT '%s': %s", pit_id, exc)
            return False

    def search_page(
        self,
        pit_id: str,
        page_size: int = 500,
        search_after: Optional[Sequence[Any]] = None,
        sort: Optional[Sequence[Dict[str, str]]] = None,
        keep_alive: str = "5m",
    ) -> List[Dict[str, Any]]:
        """Ambil satu halaman hit dari Point-In-Time memakai search_after.

        Parameters
        ----------
        pit_id : str
            ID Point-In-Time yang aktif.
        page_size : int
            Jumlah hit per halaman.
        search_after : Sequence[Any] | None
            Nilai cursor dari hit terakhir halaman sebelumnya.
        sort : Sequence[Dict[str, str]] | None
            Kriteria sort (default: [{"@timestamp": "asc"}, {"id": "asc"}]).
        keep_alive : str
            Durasi perpanjangan keep_alive PIT.

        Returns
        -------
        List[Dict[str, Any]]
            Daftar objek hit OpenSearch mentah.
        """
        sort_criteria = sort or [{"@timestamp": "asc"}, {"id": "asc"}]
        body: Dict[str, Any] = {
            "size": page_size,
            "pit": {"id": pit_id, "keep_alive": keep_alive},
            "sort": list(sort_criteria),
            "track_total_hits": False,
        }
        if search_after:
            body["search_after"] = list(search_after)

        resp = self._request("POST", "/_search", json_data=body)
        data = resp.json()
        hits_container = data.get("hits", {})
        return list(hits_container.get("hits", []))
