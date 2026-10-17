"""Konfigurasi domain dan konstanta acuan penelitian RBTA + Isolation Forest.

Satu-satunya sumber untuk:
- AGENT_CRITICALITY
- GROUP_SEVERITY_WEIGHT
- CRITICAL_MITRE_TACTICS
"""

from typing import Sequence

# Kritikalitas agent (skala 1-4: Low=1, Medium=2, High=3, Critical=4).
# Pemetaan kritikalitas aset domain untuk infrastruktur UPT TIK INSTIKI.
AGENT_CRITICALITY: dict[str, int] = {
    "soc-1": 1,
    "pusatkarir": 3,
    "dfir-iris": 4,
    "siput": 2,
    "proxy-manager": 3,
    "e-kuesioner": 2,
    "sads": 3,
    "dvwa": 1,
    "wazuh-soc": 1,
}

DEFAULT_AGENT_CRITICALITY: int = 1

CRITICALITY_LABEL_TO_SCORE: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "unknown": 1,
}

CRITICALITY_SCORE_TO_LABEL: dict[int, str] = {
    4: "critical",
    3: "high",
    2: "medium",
    1: "low",
}


def get_agent_criticality(agent_name: str | None, agent_id: str | None = None) -> int:
    """Tentukan skor kritikalitas agent (1-4) dari nama atau ID agent.

    Parameters
    ----------
    agent_name : str | None
        Nama agent (mis. 'dfir-iris', 'pusatkarir').
    agent_id : str | None, optional
        ID agent.

    Returns
    -------
    int
        Skor kritikalitas dalam rentang [1, 4].
    """
    if agent_name:
        clean_name = str(agent_name).strip().lower()
        if clean_name in AGENT_CRITICALITY:
            return AGENT_CRITICALITY[clean_name]

    if agent_id:
        clean_id = str(agent_id).strip().lower()
        if clean_id in AGENT_CRITICALITY:
            return AGENT_CRITICALITY[clean_id]

    return DEFAULT_AGENT_CRITICALITY


# Bobot severity rule group.
# Urutan semantik rule group diturunkan dari rata-rata severity dan analisis domain.
GROUP_SEVERITY_WEIGHT: dict[str, int] = {
    "attack": 10,
    "sql_injection": 10,
    "authentication_failed": 9,
    "access_control": 8,
    "pam": 7,
    "web": 7,
    "virus": 7,
    "nginx": 6,
    "audit": 6,
    "clamd": 6,
    "accesslog": 5,
    "system_error": 5,
    "audit_selinux": 5,
    "syscheck": 5,
    "syscheck_file": 5,
    "syscheck_entry_modified": 5,
    "syscheck_entry_added": 4,
    "authentication_success": 3,
    "freshclam": 3,
    "syslog": 3,
    "rootcheck": 2,
    "ossec": 1,
}

DEFAULT_RULE_GROUP_WEIGHT: int = 2


def resolve_primary_rule_group(groups: Sequence[str] | None) -> str:
    """Pilih rule group primer berdasarkan bobot severity.

    Bila ada beberapa group, dipilih group dengan bobot severity tertinggi.
    Bila bobotnya sama, dipertahankan kemunculan pertama sesuai urutan rule Wazuh.

    Parameters
    ----------
    groups : Sequence[str] | None
        Daftar nama rule group dari definisi rule Wazuh.

    Returns
    -------
    str
        Nama rule group primer.
    """
    if not groups:
        return "unknown"

    clean_groups = [str(g).strip().lower() for g in groups if str(g).strip()]
    if not clean_groups:
        return "unknown"

    return max(clean_groups, key=lambda g: GROUP_SEVERITY_WEIGHT.get(g, DEFAULT_RULE_GROUP_WEIGHT))


# Taktik MITRE ATT&CK kritis.
# Himpunan taktik berisiko tinggi yang menaikkan signifikansi ancaman.
CRITICAL_MITRE_TACTICS: frozenset[str] = frozenset({
    "Execution",
    "Lateral Movement",
    "Credential Access",
    "Exfiltration",
    "Privilege Escalation",
    "Defense Evasion",
})

_CRITICAL_MITRE_TACTICS_LOWER: frozenset[str] = frozenset(
    t.lower() for t in CRITICAL_MITRE_TACTICS
)


def has_critical_mitre_tactic(tactics: Sequence[str] | None) -> bool:
    """Periksa apakah ada taktik dalam sequence yang termasuk CRITICAL_MITRE_TACTICS.

    Parameters
    ----------
    tactics : Sequence[str] | None
        List atau tuple nama taktik MITRE.

    Returns
    -------
    bool
        True bila minimal satu taktik kritis ada, False jika tidak.
    """
    if not tactics:
        return False
    return any(str(t).strip().lower() in _CRITICAL_MITRE_TACTICS_LOWER for t in tactics if t)
