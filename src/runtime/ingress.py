"""Boundary ingress collector dan webhook yang terautentikasi."""

from dataclasses import dataclass
from typing import Any, Dict, Optional, Set

from src.contracts.raw_alert import CanonicalRawAlert
from src.etl.wazuh_canonicalizer import CanonicalizationError, canonicalize_wazuh_alert


class IngressPayloadError(ValueError):
    """Dilempar bila payload ingress tidak terotorisasi, tidak punya atribut wajib, atau rusak."""
    pass


@dataclass(frozen=True)
class IngressResult:
    """Hasil pemrosesan ingress collector."""

    status: str
    alert_id: Optional[str]
    is_duplicate: bool
    canonical_alert: Optional[CanonicalRawAlert]


class CollectorIngressBoundary:
    """Boundary transport idempoten untuk menerima alert yang di-push dari collector kampus.

    Parameters
    ----------
    api_key : str | None
        Shared secret / Bearer token opsional untuk autentikasi.
    """

    def __init__(self, api_key: Optional[str] = None) -> None:
        self.api_key: Optional[str] = api_key

    def process_incoming(
        self,
        payload: Dict[str, Any],
        auth_header: Optional[str] = None,
    ) -> IngressResult:
        """Autentikasi, validasi, dan kanonisasi payload raw alert yang masuk.

        Parameters
        ----------
        payload : Dict[str, Any]
            Objek JSON raw alert.
        auth_header : str | None
            Header HTTP Authorization (mis. 'Bearer <token>').

        Returns
        -------
        IngressResult
            Hasil pemrosesan: apakah alert baru atau duplikat, beserta representasi kanonisnya.

        Raises
        ------
        IngressPayloadError
            Bila autentikasi gagal atau payload rusak.
        """
        # Autentikasi.
        if self.api_key:
            expected_auth = f"Bearer {self.api_key}"
            if auth_header != expected_auth and auth_header != self.api_key:
                raise IngressPayloadError("Unauthorized collector ingress request")

        # Kanonisasi.
        try:
            canonical_alert = canonicalize_wazuh_alert(payload)
        except (CanonicalizationError, Exception) as exc:
            raise IngressPayloadError(f"Malformed raw alert payload: {exc}") from exc

        alert_id = canonical_alert.wazuh_alert_id
        return IngressResult(
            status="accepted",
            alert_id=alert_id,
            is_duplicate=False,
            canonical_alert=canonical_alert,
        )

    def ingest(
        self,
        payload: Dict[str, Any],
        authorization: Optional[str] = None,
    ) -> CanonicalRawAlert:
        """Shortcut yang langsung mengembalikan alert kanonis."""
        res = self.process_incoming(payload, auth_header=authorization)
        if res.canonical_alert is None:
            raise IngressPayloadError("Failed to produce canonical alert")
        return res.canonical_alert
