"""Event flat dari custom API harus terpetakan ke alert kanonis tanpa mengubah canonicalizer."""

import pytest

from src.etl.wazuh_canonicalizer import canonicalize_wazuh_alert
from src.ingestion.flat_api_adapter import flat_api_event_to_raw


def _rootcheck_event():
    return {
        "id": "OmBo_6ABLQ03QLPUqo49",
        "timestamp": "2026-10-03T01:37:15.128000Z",
        "agent_id": "005",
        "agent_name": "rbta-arya",
        "rule_id": "510",
        "rule_description": "Host-based anomaly detection event (rootcheck).",
        "rule_level": 7,
        "rule_groups": ["ossec", "rootcheck"],
        "location": "rootcheck",
        "decoder": None,
        "message": "File '/dev/.lxc/proc/version_signature' present on /dev. Possible hidden file.",
        "details": {"manager": {"name": "wazuh.manager"}},
    }


def test_flat_rootcheck_maps_to_canonical():
    raw = flat_api_event_to_raw(_rootcheck_event())
    alert = canonicalize_wazuh_alert(raw)
    assert alert.wazuh_alert_id == "OmBo_6ABLQ03QLPUqo49"
    assert alert.agent_id == "005"
    assert alert.agent_name == "rbta-arya"
    assert alert.rule_id == "510"
    assert alert.rule_level == 7
    assert alert.rule_group_primary == "rootcheck"
    assert alert.metadata["rule_description"] == "Host-based anomaly detection event (rootcheck)."


def test_flat_sca_maps_to_canonical():
    evt = {
        "id": "pGDZ_KABLQ03QLPUHo2H",
        "timestamp": "2026-10-02T13:41:18.262000Z",
        "agent_id": "005",
        "agent_name": "rbta-arya",
        "rule_id": "19007",
        "rule_description": "CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0.: Ensure permissions on /etc/shells are configured.",
        "rule_level": 7,
        "rule_groups": ["sca"],
        "location": "sca",
        "decoder": None,
        "message": "CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0.: Ensure permissions on /etc/shells are configured.",
        "details": {"manager": {"name": "wazuh.manager"}},
    }
    alert = canonicalize_wazuh_alert(flat_api_event_to_raw(evt))
    assert alert.rule_group_primary == "sca"
    assert alert.rule_id == "19007"


def test_flat_missing_rule_id_rejected():
    bad = _rootcheck_event()
    del bad["rule_id"]
    with pytest.raises((ValueError, KeyError)):
        canonicalize_wazuh_alert(flat_api_event_to_raw(bad))
