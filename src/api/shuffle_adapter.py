"""Forwarder webhook Shuffle SOAR dengan retry dan header idempotensi event."""

import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple
import requests

from src.contracts.scored_meta_alert import ScoredMetaAlert

logger = logging.getLogger(__name__)

@dataclass(frozen=True)
class ShuffleDeliveryResult:
    success: bool
    status_code: int = 0
    error: str = ""
    attempts: int = 0

    def __bool__(self) -> bool:
        return self.success

class ShuffleForwarderError(RuntimeError):
    """Dilempar bila pengiriman webhook ke Shuffle gagal."""
    pass


class ShuffleWebhookForwarder:
    """Mengirim MetaAlert yang sudah final dan diskor ke webhook workflow Shuffle SOAR.

    Parameters
    ----------
    webhook_url : str
        URL eksekusi webhook Shuffle tujuan.
    api_key : str | None
        Bearer token webhook (opsional).
    timeout : Tuple[float, float]
        (connect_timeout, read_timeout) dalam detik.
    max_retries : int
        Batas percobaan ulang saat error jaringan sementara.
    """

    def __init__(
        self,
        webhook_url: str,
        api_key: Optional[str] = None,
        timeout: Tuple[float, float] = (5.0, 15.0),
        max_retries: int = 3,
        sleep_fn=time.sleep,
    ) -> None:
        self.webhook_url: str = webhook_url
        self.api_key: Optional[str] = api_key
        self.timeout: Tuple[float, float] = timeout
        self.max_retries: int = max_retries
        self._session = requests.Session()
        self._sleep_fn = sleep_fn

    def forward(self, scored_meta: ScoredMetaAlert) -> ShuffleDeliveryResult:
        """Kirim payload meta-alert terskor ke webhook Shuffle dengan header X-Event-ID yang idempoten.

        Parameters
        ----------
        scored_meta : ScoredMetaAlert
            Meta-alert terskor yang akan dikirim.

        Returns
        -------
        bool
            True bila pengiriman berhasil (HTTP 200/202).
        """
        payload: Dict[str, Any] = {
            "meta_id": scored_meta.meta_id,
            "agent_id": scored_meta.agent_id,
            "agent_name": scored_meta.agent_name,
            "rule_group_primary": scored_meta.rule_group_primary,
            "start_time": scored_meta.start_time.isoformat(),
            "end_time": scored_meta.end_time.isoformat(),
            "alert_count": scored_meta.alert_count,
            "max_severity": scored_meta.max_severity,
            "mitre_tactics": list(scored_meta.mitre_tactics),
            "seven_features": dict(scored_meta.seven_features),
            "raw_model_score": scored_meta.raw_model_score,
            "anomaly_score": scored_meta.anomaly_score,
            "threshold_used": scored_meta.threshold_used,
            "decision": scored_meta.decision,
            "action": scored_meta.action,
            "escalate": scored_meta.escalate,
            "model_version": scored_meta.model_version,
            "source_alert_ids": list(scored_meta.source_alert_ids),
        }

        headers: Dict[str, str] = {
            "Content-Type": "application/json",
            "X-Event-ID": f"rbta-meta-{scored_meta.meta_id}",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        for attempt in range(1, self.max_retries + 1):
            try:
                resp = self._session.post(
                    self.webhook_url,
                    headers=headers,
                    json=payload,
                    timeout=self.timeout,
                    verify=True,
                )
                if resp.status_code in (200, 201, 202, 204):
                    return ShuffleDeliveryResult(success=True, status_code=resp.status_code, attempts=attempt)
                if resp.status_code == 429 or resp.status_code >= 500:
                    if attempt < self.max_retries:
                        delay = min(30.0, (2 ** (attempt - 1)) * 0.5)
                        self._sleep_fn(delay)
                        continue
                # 4xx tidak perlu di-retry.
                if 400 <= resp.status_code < 500:
                    return ShuffleDeliveryResult(success=False, status_code=resp.status_code, error=resp.text, attempts=attempt)
            except Exception as exc:
                if attempt >= self.max_retries:
                    return ShuffleDeliveryResult(success=False, error=str(exc), attempts=attempt)
                delay = min(30.0, (2 ** (attempt - 1)) * 0.5)
                self._sleep_fn(delay)
        return ShuffleDeliveryResult(success=False, error="Max retries exhausted", attempts=self.max_retries)
