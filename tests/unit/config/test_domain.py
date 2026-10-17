"""Unit test konstanta domain penelitian yang terpusat."""
import pytest
from src.config.domain import (
    AGENT_CRITICALITY,
    CRITICAL_MITRE_TACTICS,
    DEFAULT_AGENT_CRITICALITY,
    DEFAULT_RULE_GROUP_WEIGHT,
    GROUP_SEVERITY_WEIGHT,
    get_agent_criticality,
    has_critical_mitre_tactic,
    resolve_primary_rule_group,
)


def test_agent_criticality_mapping():
    """Nama agent yang dikenal dipetakan ke skor kritikalitas 1-4."""
    assert get_agent_criticality("dfir-iris") == 4
    assert get_agent_criticality("pusatkarir") == 3
    assert get_agent_criticality("proxy-manager") == 3
    assert get_agent_criticality("sads") == 3
    assert get_agent_criticality("siput") == 2
    assert get_agent_criticality("e-kuesioner") == 2
    assert get_agent_criticality("soc-1") == 1
    assert get_agent_criticality("dvwa") == 1


def test_agent_criticality_case_insensitivity_and_whitespace():
    """Pencarian kritikalitas agent tidak peka huruf besar/kecil dan whitespace."""
    assert get_agent_criticality("  DFIR-IRIS  ") == 4
    assert get_agent_criticality("PusatKarir") == 3
    assert get_agent_criticality("DVWA") == 1


def test_agent_criticality_unknown_default():
    """Agent tak dikenal default ke 1 (Low) tanpa error."""
    assert get_agent_criticality("unknown-server") == DEFAULT_AGENT_CRITICALITY
    assert get_agent_criticality(None) == DEFAULT_AGENT_CRITICALITY
    assert get_agent_criticality("") == DEFAULT_AGENT_CRITICALITY


def test_group_severity_weight_values():
    """Group prioritas tinggi punya bobot lebih tinggi dari group prioritas rendah."""
    assert GROUP_SEVERITY_WEIGHT["attack"] == 10
    assert GROUP_SEVERITY_WEIGHT["sql_injection"] == 10
    assert GROUP_SEVERITY_WEIGHT["authentication_failed"] == 9
    assert GROUP_SEVERITY_WEIGHT["ossec"] == 1
    assert GROUP_SEVERITY_WEIGHT["attack"] > GROUP_SEVERITY_WEIGHT["syslog"]


def test_resolve_primary_rule_group_single():
    """Resolusi satu rule group."""
    assert resolve_primary_rule_group(["syslog"]) == "syslog"
    assert resolve_primary_rule_group(["attack"]) == "attack"


def test_resolve_primary_rule_group_multiple():
    """Beberapa rule group memilih bobot tertinggi."""
    groups = ["pam", "syslog", "authentication_success"]
    # pam (7) > authentication_success (3) == syslog (3)
    assert resolve_primary_rule_group(groups) == "pam"

    groups2 = ["web", "accesslog", "sql_injection", "attack"]
    # sql_injection (10) muncul sebelum attack (10), keduanya bernilai 10.
    assert resolve_primary_rule_group(groups2) in ("sql_injection", "attack")
    # deterministik: yang tertinggi pertama kali ditemukan
    assert resolve_primary_rule_group(groups2) == "sql_injection"


def test_resolve_primary_rule_group_empty_or_unknown():
    """Penanganan daftar rule group kosong atau tak dikenal."""
    assert resolve_primary_rule_group([]) == "unknown"
    assert resolve_primary_rule_group(["custom_unlisted_group"]) == "custom_unlisted_group"


def test_critical_mitre_tactics_membership():
    """Enam taktik MITRE kritis acuan."""
    expected = {
        "Execution",
        "Lateral Movement",
        "Credential Access",
        "Exfiltration",
        "Privilege Escalation",
        "Defense Evasion",
    }
    assert CRITICAL_MITRE_TACTICS == expected


def test_has_critical_mitre_tactic():
    """Deteksi taktik MITRE kritis di dalam list."""
    assert has_critical_mitre_tactic(["Defense Evasion", "Initial Access"]) is True
    assert has_critical_mitre_tactic(["Initial Access", "Reconnaissance"]) is False
    assert has_critical_mitre_tactic([]) is False
    assert has_critical_mitre_tactic(["credential access"]) is True  # tidak peka huruf besar/kecil
