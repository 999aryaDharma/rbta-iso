"""Client API perantara kustom untuk bentuk event flat yang sudah dibekukan.

Memanggil API perantara kampus (``GET /events?limit&offset``) yang mengembalikan
``{events, total, limit, offset}`` — BUKAN ``:9200/_search`` milik Indexer dan BUKAN
jalur push collector. Setiap event flat diterjemahkan lewat ``flat_api_adapter``
menjadi dict raw bersarang yang diterima canonicalizer, sehingga Research Core tidak berubah.
"""

import logging
import os
import time
from typing import Any, Dict, List, Optional

import requests

from src.contracts.raw_alert import CanonicalRawAlert
from src.etl.wazuh_canonicalizer import canonicalize_wazuh_alert
from src.ingestion.flat_api_adapter import flat_api_event_to_raw

logger = logging.getLogger(__name__)


class WazuhAPIError(RuntimeError):
    """Error dasar untuk operasi custom API."""


class WazuhAPIAuthError(WazuhAPIError):
    """Dilempar saat 401/403, tanpa retry dan tanpa response body."""


class WazuhAPIClient:
    """Client minimal untuk flat API (paginasi limit/offset)."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        session_cookie: Optional[str] = None,
        session_cookie_name: str = "guardins_session",
        username: Optional[str] = None,
        password: Optional[str] = None,
        login_path: Optional[str] = None,
        login_field: Optional[str] = None,
        password_field: Optional[str] = None,
        session_file: Optional[str] = None,
        verify_tls: Optional[Any] = None,
        timeout: tuple[float, float] = (5.0, 30.0),
        max_retries: int = 3,
        sleep_fn=None,
        random_fn=None,
        events_path: str = "/events",
    ) -> None:
        self.base_url: str = (base_url or os.getenv("WAZUH_API_URL", "")).rstrip("/")
        if not self.base_url:
            raise ValueError("WAZUH_API_URL (or base_url) is required for custom API mode")
        self.api_key: Optional[str] = api_key or os.getenv("WAZUH_API_KEY")
        self.session_cookie: Optional[str] = session_cookie or os.getenv("WAZUH_API_SESSION_COOKIE")
        self.session_cookie_name: str = session_cookie_name
        self.username: Optional[str] = username or os.getenv("WAZUH_API_USERNAME")
        self.password: Optional[str] = password or os.getenv("WAZUH_API_PASSWORD")
        self.login_path: str = login_path or os.getenv("WAZUH_API_LOGIN_PATH", "/auth/login")
        self.login_field: str = login_field or os.getenv("WAZUH_API_LOGIN_FIELD", "email")
        self.password_field: str = password_field or os.getenv("WAZUH_API_PASSWORD_FIELD", "password")
        self.session_file: Optional[str] = session_file or os.getenv("WAZUH_API_SESSION_FILE")
        if verify_tls is None:
            tls_setting = os.getenv("WAZUH_API_VERIFY_TLS", "true").strip().lower()
            if tls_setting not in ("true", "false"):
                raise ValueError("WAZUH_API_VERIFY_TLS must be true or false")
            if tls_setting == "true":
                from pathlib import Path as _Path

                ca_path = os.getenv("WAZUH_API_CA_PATH")
                if ca_path:
                    if not _Path(ca_path).is_file():
                        raise FileNotFoundError(
                            f"WAZUH_API_CA_PATH points to missing file: {ca_path}"
                        )
                    verify_tls = ca_path
                else:
                    verify_tls = True
            else:
                verify_tls = False
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.max_retries = max_retries
        self.events_path = events_path
        self._sleep_fn = sleep_fn or time.sleep
        self._random_fn = random_fn or (lambda: __import__("random").random())
        self._session = requests.Session()
        self._load_session_file()

    # Penyimpanan cookie sesi di file + watcher.

    def _load_session_file(self) -> Optional[str]:
        """Pakai cookie dari file sesi bila berbeda dengan yang ada di memori.

        Dipanggil saat init dan sebelum setiap request, jadi file yang diperbarui dari luar
        (operator/cron) langsung terpakai tanpa restart. Nilai cookie tidak pernah di-log.
        """
        if not self.session_file:
            return self.session_cookie
        try:
            from pathlib import Path as _Path
            import json as _json

            text = _Path(self.session_file).read_text(encoding="utf-8")
            data = _json.loads(text)
            cookie = data.get("cookie") if isinstance(data, dict) else None
            if cookie and str(cookie).strip() and cookie != self.session_cookie:
                self.session_cookie = str(cookie)
                logger.info("Custom API session cookie reloaded from session file.")
        except FileNotFoundError:
            pass
        except Exception as exc:
            logger.warning("Ignoring unreadable custom API session file: %s", type(exc).__name__)
        return self.session_cookie

    def _save_session_file(self, cookie: str) -> None:
        """Simpan cookie hasil login baru (best effort, 0o600 di POSIX)."""
        self.session_cookie = cookie
        if not self.session_file:
            return
        try:
            import json as _json

            payload = _json.dumps({"cookie": cookie})
            if os.name != "nt":
                import stat as _stat

                fd = os.open(self.session_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(payload)
            else:
                from pathlib import Path as _Path

                _Path(self.session_file).write_text(payload, encoding="utf-8")
        except Exception as exc:
            logger.warning("Could not persist custom API session file: %s", type(exc).__name__)

    # Autentikasi.

    def login(self) -> str:
        """POST ke kontrak login, simpan sesi dari Set-Cookie.

        Mengembalikan nilai cookie baru. Melempar :class:`WazuhAPIAuthError` bila
        kredensial service itu sendiri ditolak (tanpa loop retry).
        """
        if not self.username or not self.password:
            raise WazuhAPIAuthError("Custom API login requires WAZUH_API_USERNAME and WAZUH_API_PASSWORD")
        url = f"{self.base_url}/{self.login_path.lstrip('/')}"
        last_exc: Optional[Exception] = None
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = self._session.request(
                    method="POST",
                    url=url,
                    headers={"Accept": "application/json", "Content-Type": "application/json"},
                    json={self.login_field: self.username, self.password_field: self.password},
                    verify=self.verify_tls,
                    timeout=self.timeout,
                )
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
                last_exc = exc
                if attempt >= self.max_retries:
                    raise WazuhAPIError(
                        f"Network failure calling custom API login at {self.base_url}"
                    ) from exc
                self._sleep_fn(min(30.0, (2 ** (attempt - 1)) * 0.5) + self._random_fn() * 0.5)
                continue
            if resp.status_code in (401, 403):
                raise WazuhAPIAuthError(
                    f"Custom API login rejected ({resp.status_code}) at {self.base_url}"
                )
            if resp.status_code in (429, 502, 503, 504) and attempt < self.max_retries:
                last_exc = WazuhAPIError(f"Transient HTTP {resp.status_code}")
                self._sleep_fn(min(30.0, (2 ** (attempt - 1)) * 0.5) + self._random_fn() * 0.5)
                continue
            try:
                resp.raise_for_status()
            except requests.exceptions.HTTPError as exc:
                raise WazuhAPIError(
                    f"HTTP error ({resp.status_code}) calling custom API login at {self.base_url}"
                ) from exc
            jar = getattr(resp, "cookies", None)
            cookie = jar.get(self.session_cookie_name) if jar is not None else None
            if not cookie:
                raise WazuhAPIError(
                    f"Custom API login response carried no '{self.session_cookie_name}' cookie"
                )
            self._save_session_file(str(cookie))
            logger.info("Custom API re-login succeeded; session cookie refreshed.")
            return str(cookie)
        raise WazuhAPIError(f"Exceeded max retries calling custom API login at {self.base_url}") from last_exc

    def _headers(self) -> Dict[str, str]:
        self._load_session_file()
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        if self.session_cookie:
            headers["Cookie"] = f"{self.session_cookie_name}={self.session_cookie}"
        return headers

    def fetch_page(self, limit: int = 50, offset: int = 0) -> Dict[str, Any]:
        """Ambil satu halaman; satu kali auto-relogin saat 401, selain itu langsung gagal."""
        url = f"{self.base_url}/{self.events_path.lstrip('/')}"
        last_exc: Optional[Exception] = None
        refreshed = False
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = self._session.request(
                    method="GET",
                    url=url,
                    headers=self._headers(),
                    params={"limit": limit, "offset": offset},
                    verify=self.verify_tls,
                    timeout=self.timeout,
                )
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
                last_exc = exc
                if attempt >= self.max_retries:
                    raise WazuhAPIError(
                        f"Network failure calling custom API at {self.base_url}"
                    ) from exc
                self._sleep_fn(min(30.0, (2 ** (attempt - 1)) * 0.5) + self._random_fn() * 0.5)
                continue
            if resp.status_code in (401, 403):
                if resp.status_code == 401 and self.username and self.password and not refreshed:
                    refreshed = True
                    self.login()
                    continue
                raise WazuhAPIAuthError(
                    f"Authentication failed ({resp.status_code}) against custom API at {self.base_url}"
                )
            if resp.status_code in (429, 502, 503, 504) and attempt < self.max_retries:
                last_exc = WazuhAPIError(f"Transient HTTP {resp.status_code}")
                self._sleep_fn(min(30.0, (2 ** (attempt - 1)) * 0.5) + self._random_fn() * 0.5)
                continue
            try:
                resp.raise_for_status()
            except requests.exceptions.HTTPError as exc:
                raise WazuhAPIError(
                    f"HTTP error ({resp.status_code}) calling custom API at {self.base_url}"
                ) from exc
            try:
                data = resp.json()
            except Exception as exc:
                raise WazuhAPIError("Custom API response is not valid JSON") from exc
            if not isinstance(data, dict) or not isinstance(data.get("events"), list):
                raise WazuhAPIError("Malformed custom API response: missing 'events' list")
            return data
        raise WazuhAPIError(f"Exceeded max retries calling custom API at {self.base_url}") from last_exc

    def fetch_all_canonical(self, limit: int = 50) -> List[CanonicalRawAlert]:
        """Paginasi limit/offset sampai offset >= total; kembalikan alert kanonis."""
        out: List[CanonicalRawAlert] = []
        offset = 0
        while True:
            page = self.fetch_page(limit=limit, offset=offset)
            events = page.get("events", [])
            total = page.get("total", offset + len(events))
            for evt in events:
                out.append(canonicalize_wazuh_alert(flat_api_event_to_raw(evt)))
            offset += len(events)
            if not events or offset >= int(total):
                break
        return out
