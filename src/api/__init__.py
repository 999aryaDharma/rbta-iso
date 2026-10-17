"""Paket REST API operasional, integrasi Shuffle SOAR, dan format pesan Telegram."""

__all__ = [
    "ShuffleForwarderError",
    "ShuffleWebhookForwarder",
    "create_app",
    "format_telegram_alert",
]


def __getattr__(name: str):
    """Muat helper API secara lazy agar tidak terjadi import cycle dengan worker runtime."""
    if name == "create_app":
        from src.api.app import create_app
        return create_app
    if name in {"ShuffleForwarderError", "ShuffleWebhookForwarder"}:
        from src.api.shuffle_adapter import ShuffleForwarderError, ShuffleWebhookForwarder
        return {"ShuffleForwarderError": ShuffleForwarderError, "ShuffleWebhookForwarder": ShuffleWebhookForwarder}[name]
    if name == "format_telegram_alert":
        from src.runtime.telegram_formatter import format_telegram_alert
        return format_telegram_alert
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
