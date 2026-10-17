"""
telegram_notifier.py  —  Notification Format Generator untuk Telegram & SOAR
==============================================================================
Menghasilkan format notifikasi yang informatif dan compact (4 baris) untuk
menunjukkan bahwa sistem RBTA+IF beroperasional optimal di sidang.

Format standar:
  Line 1: [ESCALATE] <agent> | <rule_group> | <decision>
  Line 2: Severity: X/15  |  Y alerts dalam Z menit
  Line 3: Mulai: HH:MM WITA  |  Selesai: HH:MM WITA
  Line 4: Score anomali: A.BC

Setiap komponen harus langsung menjawab pertanyaan analis:
  1. Ada incident apa? (agent + rule_group)
  2. Seberapa parah? (severity dan alert count)
  3. Berapa lama? (start_time s/d end_time)
  4. Berapa anomali score? (confidence dari IF)
"""

import logging
from datetime import datetime

import pandas as pd

log = logging.getLogger(__name__)


# Format Telegram Compact (4 baris)

def format_telegram_notification(
    agent_name:       str,
    rule_groups:      str,
    decision:         str,
    max_severity:     int,
    alert_count:      int,
    duration_minutes: int,
    start_time:       datetime | str | None = None,
    end_time:         datetime | str | None = None,
    anomaly_score:    float = 0.0,
    severity_max:     int = 15,  # Referensi severity tertinggi (Wazuh level 15)
) -> str:
    """
    Generate notifikasi Telegram 4-baris untuk eskalasi IF.

    Parameters
    ----------
    agent_name       : str, nama agent
    rule_groups      : str, rule group utama (e.g., 'authentication_failed')
    decision         : str, hasil keputusan IF (e.g., 'CRITICAL', 'SUSPICIOUS')
    max_severity     : int, rule level terendah-tertinggi (1-15)
    alert_count      : int, jumlah alert dalam bucket
    duration_minutes : int, durasi insiden dalam menit
    start_time       : datetime|str|None, waktu mulai (akan di-parse)
    end_time         : datetime|str|None, waktu selesai (akan di-parse)
    anomaly_score    : float, IF anomaly score (0.0-1.0)
    severity_max     : int, severity reference maximum (default 15 untuk Wazuh)

    Returns
    -------
    str — notifikasi 4-baris, siap kirim ke Telegram.

    Contoh output:
    ```
    [ESCALATE] dfir-iris | authentication_failed | CRITICAL
    Severity: 10/15  |  72 alerts dalam 8 menit
    Mulai: 02:14 WITA  |  Selesai: 02:22 WITA
    Score anomali: 0.87
    ```
    """
    # Parse start_time dan end_time
    if isinstance(start_time, str):
        try:
            start_time = pd.to_datetime(start_time)
        except Exception:
            start_time = None
    if isinstance(end_time, str):
        try:
            end_time = pd.to_datetime(end_time)
        except Exception:
            end_time = None

    # Line 1: [ACTION] agent | rule_group | decision
    action_symbol = "[ESCALATE]" if decision in ("CRITICAL", "SUSPICIOUS") else "[DIGEST]"
    line1 = f"{action_symbol} {agent_name} | {rule_groups} | {decision}"

    # Line 2: Severity: X/MAX | Y alerts dalam Z menit
    line2 = f"Severity: {max_severity}/{severity_max}  |  {alert_count} alerts dalam {duration_minutes} menit"

    # Line 3: Mulai: HH:MM WITA | Selesai: HH:MM WITA
    if start_time and end_time:
        # Asumsikan WITA adalah UTC+8 (Indonesian timezone)
        start_str = pd.to_datetime(start_time).strftime("%H:%M") if start_time else "??:??"
        end_str   = pd.to_datetime(end_time).strftime("%H:%M") if end_time else "??:??"
        line3 = f"Mulai: {start_str} WITA  |  Selesai: {end_str} WITA"
    else:
        line3 = "Mulai: ??:?? WITA  |  Selesai: ??:?? WITA"

    # Line 4: Score anomali: X.YZ (2 desimal)
    score_str = f"{anomaly_score:.2f}"
    line4 = f"Score anomali: {score_str}"

    notification = f"{line1}\n{line2}\n{line3}\n{line4}"
    return notification


def format_telegram_batch(
    df_escalated: pd.DataFrame,
    severity_max: int = 15,
) -> list[str]:
    """
    Generate list notifikasi untuk semua escalated meta-alerts.

    Parameters
    ----------
    df_escalated : pd.DataFrame
        DataFrame hasil filter escalate==1 dari isolation_forest.py
        Harus memiliki kolom:
        - agent_name, rule_groups, decision
        - max_severity, alert_count, duration_sec
        - start_time, end_time, anomaly_score

    Returns
    -------
    list[str] — daftar notifikasi, masing-masing siap untuk Telegram.
    """
    notifications = []
    
    for _, row in df_escalated.iterrows():
        try:
            duration_minutes = int(row.get("duration_sec", 0) / 60)
            notif = format_telegram_notification(
                agent_name       = str(row.get("agent_name", "unknown")),
                rule_groups      = str(row.get("rule_groups", "unknown")),
                decision         = str(row.get("decision", "NOISE")),
                max_severity     = int(row.get("max_severity", 1)),
                alert_count      = int(row.get("alert_count", 1)),
                duration_minutes = max(1, duration_minutes),
                start_time       = row.get("start_time"),
                end_time         = row.get("end_time"),
                anomaly_score    = float(row.get("anomaly_score", 0.0)),
                severity_max     = severity_max,
            )
            notifications.append(notif)
        except Exception as e:
            log.warning("Gagal format notifikasi untuk baris: %s", e)
            continue
    
    return notifications


# Export ke file telegram_messages.txt

def export_telegram_messages(
    df_scored:    pd.DataFrame,
    output_path:  str = "output/telegram_messages.txt",
    severity_max: int = 15,
) -> str:
    """
    Export semua notifikasi Telegram ke file .txt dengan format rapi.

    Output file berisi:
    - Header dengan timestamp dan jumlah escalation
    - Separator untuk setiap notifikasi
    - Notifikasi 4-baris
    - Footer dengan statistik

    Parameters
    ----------
    df_scored   : pd.DataFrame, hasil scoring dari IF
    output_path : str, path output file
    severity_max: int, referensi severity max

    Returns
    -------
    str — path file yang di-generate
    """
    df_esc = df_scored[df_scored["action"] == "ESCALATE"].copy()
    n_notifications = len(df_esc)

    lines = [
        "=" * 80,
        "  TELEGRAM NOTIFICATIONS — RBTA + Isolation Forest",
        f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Total Escalations: {n_notifications}",
        "=" * 80,
        "",
    ]

    if n_notifications == 0:
        lines.append("  [No escalations to report]")
    else:
        notifications = format_telegram_batch(df_esc, severity_max=severity_max)
        for i, notif in enumerate(notifications, 1):
            lines.append(f"[Notification #{i}]")
            lines.append(notif)
            lines.append("-" * 80)
            lines.append("")

    lines.extend([
        "=" * 80,
        f"  Summary: {n_notifications} escalated incidents",
        f"  Ready to send to Telegram or SOAR platform",
        "=" * 80,
    ])

    report_text = "\n".join(lines)

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report_text)
        log.info("Telegram notifications exported to: %s", output_path)
    except Exception as e:
        log.error("Gagal export telegram notifications: %s", e)

    return output_path


# Unit Tests & Example

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    # Example 1: Single notification
    notif1 = format_telegram_notification(
        agent_name       = "dfir-iris",
        rule_groups      = "authentication_failed",
        decision         = "CRITICAL",
        max_severity     = 10,
        alert_count      = 72,
        duration_minutes = 8,
        start_time       = "2025-04-10 02:14:00",
        end_time         = "2025-04-10 02:22:00",
        anomaly_score    = 0.87,
        severity_max     = 15,
    )
    print("Example Notification #1:")
    print(notif1)
    print("\n" + "=" * 80 + "\n")

    # Example 2: Batch test dengan dummy DataFrame
    df_test = pd.DataFrame({
        "agent_name":    ["soc-1", "pusatkarir", "dfir-iris"],
        "rule_groups":   ["rootcheck", "config_changed", "sql_injection"],
        "decision":      ["SUSPICIOUS", "CRITICAL", "NOISE"],
        "max_severity":  [5, 8, 3],
        "alert_count":   [23, 156, 2],
        "duration_sec":  [300, 1800, 60],
        "start_time":    [
            "2025-04-10 02:00:00",
            "2025-04-10 05:30:00",
            "2025-04-10 08:15:00",
        ],
        "end_time":      [
            "2025-04-10 02:05:00",
            "2025-04-10 05:40:00",
            "2025-04-10 08:16:00",
        ],
        "anomaly_score": [0.72, 0.95, 0.15],
        "action":        ["ESCALATE", "ESCALATE", "SUPPRESS"],
    })

    print("Example Batch (all):")
    for notif in format_telegram_batch(df_test):
        print(notif)
        print("-" * 80)
