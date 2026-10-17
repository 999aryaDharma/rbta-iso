"""Generator deterministik fixture tests/fixtures/live_offline_parity_alerts.jsonl (T3).

Fixture ini SINTETIS dan hanya dipakai untuk membuktikan bahwa jalur offline dan live
menghasilkan agregasi + skor yang sama. Bukan data penelitian dan bukan ground truth.

Jalankan ulang (hasil identik byte demi byte):
    python tests/fixtures/generate_parity_alerts.py
"""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import random

OUT = Path(__file__).with_name("live_offline_parity_alerts.jsonl")

AGENTS = (("001", "pusatkarir", 3), ("002", "dfir-iris", 4), ("003", "soc-1", 1))
GROUPS = {
    # group: (rule_ids, level range, kemungkinan taktik MITRE)
    "authentication_failed": (("5710", "5712", "5716"), (5, 10), ("Credential Access",)),
    "syscheck": (("550", "553", "554"), (3, 7), ("Defense Evasion", "Impact")),
    "web": (("31101", "31103", "31151"), (6, 12), ("Initial Access", "Execution")),
    "pam": (("5501", "5502"), (3, 5), ()),
    "sql_injection": (("31164", "31170"), (10, 13), ("Initial Access", "Credential Access")),
}
START = datetime(2026, 9, 1, 0, 0, tzinfo=timezone.utc)


def _burst(rng, agent, group, t0, n, gap_sec, mitre_prob):
    agent_id, agent_name, crit = agent
    rule_ids, (lo, hi), tactics = GROUPS[group]
    out, t = [], t0
    for _ in range(n):
        t += timedelta(seconds=rng.randint(*gap_sec), milliseconds=rng.randint(0, 999))
        picked = sorted({x for x in tactics if rng.random() < mitre_prob})
        out.append({
            "timestamp": t.isoformat(),
            "agent_id": agent_id,
            "agent_name": agent_name,
            "rule_group_primary": group,
            "rule_level": rng.randint(lo, hi),
            "rule_id": rng.choice(rule_ids),
            "mitre_tactics": picked,
            "srcip": f"10.0.{rng.randint(0, 3)}.{rng.randint(1, 254)}" if group != "syscheck" else None,
            "agent_criticality": crit,
        })
    return out


def generate():
    rng = random.Random(20261017)
    alerts = []
    for agent in AGENTS:
        t = START + timedelta(minutes=rng.randint(0, 30))
        while len([a for a in alerts if a["agent_id"] == agent[0]]) < 120:
            group = rng.choice(list(GROUPS))
            # Jeda antar-burst campuran: < Δt (merge) dan > Δt / > 60 menit (split).
            t += timedelta(minutes=rng.choice((3, 8, 14, 22, 45, 75)))
            alerts += _burst(rng, agent, group, t, rng.randint(1, 18), (1, 90), 0.35)
    # Satu burst padat berseverity tinggi + banyak taktik pada aset kritis (variasi skor).
    attack = _burst(rng, AGENTS[1], "sql_injection", START + timedelta(hours=20), 40, (1, 20), 0.9)
    for a in attack:
        a["mitre_tactics"] = sorted(set(a["mitre_tactics"]) | {"Execution", "Exfiltration"})
    alerts += attack
    alerts.sort(key=lambda a: (a["timestamp"], a["agent_id"]))
    for i, a in enumerate(alerts):
        a["wazuh_alert_id"] = f"parity-{i:05d}"
    return alerts


if __name__ == "__main__":
    rows = generate()
    OUT.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows), encoding="utf-8", newline="\n")
    print(f"{len(rows)} alerts -> {OUT}")
