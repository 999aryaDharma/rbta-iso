"""Unit test kontrak DTO MetaAlert."""
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
import pytest
from src.contracts.meta_alert import MetaAlert


def test_meta_alert_valid_instantiation():
    """Instansiasi MetaAlert yang valid."""
    t1 = datetime(2026, 8, 28, 5, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 8, 28, 5, 15, 0, tzinfo=timezone.utc)

    meta = MetaAlert(
        meta_id=1,
        agent_id="001",
        agent_name="soc-1",
        rule_group_primary="pam",
        start_time=t1,
        end_time=t2,
        alert_count=5,
        max_severity=7,
        rule_id_distribution={"5501": 3, "5502": 2},
        severity_distribution={3: 3, 7: 2},
        mitre_tactics_unique=("Defense Evasion", "Persistence"),
        critical_mitre_present=True,
        agent_criticality=1,
        wazuh_alert_ids=("id1", "id2", "id3", "id4", "id5"),
        metadata={"custom": "val"},
    )
    assert meta.meta_id == 1
    assert meta.agent_id == "001"
    assert meta.rule_group_primary == "pam"
    assert meta.duration_sec == 900.0
    assert meta.alert_count == 5
    assert meta.max_severity == 7
    assert meta.critical_mitre_present is True
    assert meta.agent_criticality == 1
    assert len(meta.wazuh_alert_ids) == 5


def test_meta_alert_immutability():
    """Atribut MetaAlert tidak bisa diubah setelah dibuat."""
    t1 = datetime(2026, 8, 28, 5, 0, 0, tzinfo=timezone.utc)
    meta = MetaAlert(
        meta_id=1,
        agent_id="001",
        agent_name="soc-1",
        rule_group_primary="pam",
        start_time=t1,
        end_time=t1,
        alert_count=1,
        max_severity=3,
        rule_id_distribution={"5501": 1},
        severity_distribution={3: 1},
        mitre_tactics_unique=(),
        critical_mitre_present=False,
        agent_criticality=1,
        wazuh_alert_ids=("id1",),
    )
    with pytest.raises((FrozenInstanceError, AttributeError)):
        meta.alert_count = 10


def test_meta_alert_nested_distribution_immutability():
    """Map distribusi bersarang dan metadata terlindungi dari mutasi in-place."""
    t1 = datetime(2026, 8, 28, 5, 0, 0, tzinfo=timezone.utc)
    meta = MetaAlert(
        meta_id=1,
        agent_id="001",
        agent_name="soc-1",
        rule_group_primary="pam",
        start_time=t1,
        end_time=t1,
        alert_count=1,
        max_severity=3,
        rule_id_distribution={"5501": 1},
        severity_distribution={3: 1},
        mitre_tactics_unique=(),
        critical_mitre_present=False,
        agent_criticality=1,
        wazuh_alert_ids=("id1",),
        metadata={"key": "val"},
    )
    with pytest.raises(TypeError):
        meta.rule_id_distribution["5501"] = 99

    with pytest.raises(TypeError):
        meta.severity_distribution[3] = 99

    with pytest.raises(TypeError):
        meta.metadata["key"] = "new_val"


def test_meta_alert_duration_non_negative():
    """end_time >= start_time wajib terpenuhi."""
    t1 = datetime(2026, 8, 28, 5, 15, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 8, 28, 5, 0, 0, tzinfo=timezone.utc)

    with pytest.raises(ValueError, match="end_time"):
        MetaAlert(
            meta_id=1,
            agent_id="001",
            agent_name="soc-1",
            rule_group_primary="pam",
            start_time=t1,
            end_time=t2,
            alert_count=1,
            max_severity=3,
            rule_id_distribution={"5501": 1},
            severity_distribution={3: 1},
            mitre_tactics_unique=(),
            critical_mitre_present=False,
            agent_criticality=1,
            wazuh_alert_ids=("id1",),
        )


def test_meta_alert_count_positive():
    """alert_count minimal 1."""
    t1 = datetime(2026, 8, 28, 5, 0, 0, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match="alert_count"):
        MetaAlert(
            meta_id=1,
            agent_id="001",
            agent_name="soc-1",
            rule_group_primary="pam",
            start_time=t1,
            end_time=t1,
            alert_count=0,
            max_severity=3,
            rule_id_distribution={},
            severity_distribution={},
            mitre_tactics_unique=(),
            critical_mitre_present=False,
            agent_criticality=1,
            wazuh_alert_ids=(),
        )
