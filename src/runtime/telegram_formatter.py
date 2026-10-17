"""Formatter HTML Telegram kanonis (sudah di-escape) untuk notifikasi MetaAlert."""

from html import escape
from zoneinfo import ZoneInfo

from src.contracts.scored_meta_alert import ScoredMetaAlert

_WITA = ZoneInfo("Asia/Makassar")

_ID_MONTHS = (
    "Jan", "Feb", "Mar", "Apr", "Mei", "Jun",
    "Jul", "Agu", "Sep", "Okt", "Nov", "Des",
)


def _short_date(dt) -> str:
    local = dt.astimezone(_WITA)
    return f"{local.day} {_ID_MONTHS[local.month - 1]} {local.year}"


def _short_dt(dt) -> str:
    local = dt.astimezone(_WITA)
    return f"{_short_date(dt)}, {local:%H:%M}"


def _format_window(scored_meta: ScoredMetaAlert) -> str:
    start = scored_meta.start_time.astimezone(_WITA)
    end = scored_meta.end_time.astimezone(_WITA)
    if start.date() == end.date():
        return f"{_short_date(start)}, {start:%H:%M}-{end:%H:%M} WITA"
    return f"{_short_dt(start)} - {_short_dt(end)} WITA"


def format_telegram_alert(scored_meta: ScoredMetaAlert, run_id: str = "live") -> str:
    """Format MetaAlert terskor menjadi HTML Telegram yang sudah di-escape; tanpa logika routing.

    Urutan: header putusan, identitas, satu baris action, konteks dalam kalimat biasa, kalimat
    skor, provenance, batas klaim. Baris kosong memisahkan bagian agar pesan mudah dibaca di layar HP.
    """
    tactics_str = ", ".join(scored_meta.mitre_tactics) if scored_meta.mitre_tactics else "Tidak ada"
    margin = float(scored_meta.anomaly_score) - float(scored_meta.threshold_used)

    return (
        f"<b>{escape(scored_meta.decision)} · META-ALERT #{scored_meta.meta_id}</b>\n"
        f"<code>{escape(scored_meta.agent_name)} ({escape(scored_meta.agent_id)}) · "
        f"{escape(scored_meta.rule_group_primary)}</code>\n"
        f"\n"
        f"<b>Action: {escape(scored_meta.action)}</b>\n"
        f"\n"
        f"{_format_window(scored_meta)}\n"
        f"{scored_meta.alert_count} alert · level max {scored_meta.max_severity}/15\n"
        f"MITRE: {escape(tactics_str)}\n"
        f"\n"
        f"Skor {scored_meta.anomaly_score:.4f} "
        f"(ambang {scored_meta.threshold_used:.4f}, margin {margin:+.4f})\n"
        f"<code>{escape(scored_meta.model_version)} · {escape(run_id)}</code>\n"
        f"\n"
        "<i>Skor anomaly bukan bukti serangan; ini prioritas triase.</i>"
    )
