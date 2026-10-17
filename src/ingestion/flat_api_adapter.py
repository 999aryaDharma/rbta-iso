"""Adapter untuk bentuk event flat dari custom API (lihat FLAT-API-FREEZE).

Menerjemahkan JSON flat yang sudah dibekukan (id/timestamp/agent_id/agent_name/
rule_id/rule_level/rule_groups/...) menjadi dict raw Wazuh bersarang yang sudah
diterima ``canonicalize_wazuh_alert``.

Canonicalizer bersarang sengaja tidak diubah; hanya modul ini yang mengenal bentuk flat.
"""

from typing import Any, Mapping


def flat_api_event_to_raw(event: Mapping[str, Any]) -> dict[str, Any]:
    """Petakan satu event flat API ke dict raw Wazuh bersarang."""
    if not isinstance(event, Mapping):
        raise ValueError(f"Expected flat event mapping, got {type(event)}")

    raw_id = event.get("id")
    if raw_id is None or not str(raw_id).strip():
        raise ValueError("Flat event missing required 'id'")

    raw_ts = event.get("timestamp")
    if raw_ts is None or (isinstance(raw_ts, str) and not raw_ts.strip()):
        raise ValueError("Flat event missing required 'timestamp'")

    if event.get("rule_id") is None or str(event.get("rule_id")).strip() == "":
        raise ValueError("Flat event missing required 'rule_id'")
    if event.get("rule_level") is None:
        raise ValueError("Flat event missing required 'rule_level'")
    groups = event.get("rule_groups")
    if groups is None:
        raise ValueError("Flat event missing required 'rule_groups'")

    agent = {
        "id": str(event.get("agent_id", "000")),
        "name": str(event.get("agent_name", "unknown")),
    }
    rule: dict[str, Any] = {
        "id": str(event["rule_id"]),
        "level": event["rule_level"],
        "groups": list(groups) if isinstance(groups, (list, tuple)) else groups,
    }
    if event.get("rule_description") is not None:
        rule["description"] = event["rule_description"]

    raw: dict[str, Any] = {
        "id": str(raw_id),
        "timestamp": raw_ts,
        "agent": agent,
        "rule": rule,
    }
    if event.get("location") is not None:
        raw["location"] = event["location"]
    if event.get("message") is not None:
        raw["full_log"] = event["message"]
    if event.get("decoder") is not None:
        raw["decoder"] = event["decoder"]

    details = event.get("details")
    manager_name = None
    data_block = None
    if isinstance(details, Mapping):
        manager = details.get("manager")
        if isinstance(manager, Mapping) and manager.get("name") is not None:
            manager_name = manager["name"]
        data = details.get("data")
        if isinstance(data, Mapping) and data:
            data_block = dict(data)
    if manager_name is not None:
        raw["manager"] = {"name": manager_name}
    # srcip diteruskan bila perantara mengirimkannya.
    srcip = event.get("srcip")
    if srcip is None and isinstance(data_block, dict):
        srcip = data_block.get("srcip")
    if isinstance(data_block, dict):
        if srcip is not None:
            data_block["srcip"] = srcip
        raw["data"] = data_block
    elif srcip is not None:
        raw["data"] = {"srcip": srcip}

    return raw


def flat_api_page_to_raw_list(page: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Petakan satu response API berhalaman ({events,total,limit,offset}) ke list raw."""
    if not isinstance(page, Mapping):
        raise ValueError(f"Expected page mapping, got {type(page)}")
    events = page.get("events", [])
    if not isinstance(events, list):
        raise ValueError("Page 'events' must be a list")
    return [flat_api_event_to_raw(e) for e in events]
