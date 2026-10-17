"""Integration test: integritas pemetaan tanpa kehilangan alert dan determinisme."""
from collections import Counter
from datetime import datetime, timedelta, timezone
import random
import pytest

from src.contracts.meta_alert import MetaAlert
from src.contracts.raw_alert import CanonicalRawAlert
from src.rbta.engine import RBTAEngine
from src.rbta.reorder_buffer import LosslessReorderBuffer


def generate_synthetic_stream() -> list[CanonicalRawAlert]:
    """Bangkitkan aliran kanonis sintetis yang deterministik dan mencakup semua edge case yang dibutuhkan."""
    rng = random.Random(1337)
    base_t = datetime(2026, 8, 28, 8, 0, 0, tzinfo=timezone.utc)
    stream: list[CanonicalRawAlert] = []

    # Agent 001: 120 event untuk menguji warmup (100) + ETW adaptif (20).
    curr_t = base_t
    for i in range(120):
        # Tambahkan sedikit jitter/burst.
        step = rng.choice([2, 5, 10, 15, 20])
        curr_t += timedelta(seconds=step)
        stream.append(
            CanonicalRawAlert(
                wazuh_alert_id=f"a001_{i:04d}",
                timestamp=curr_t,
                agent_id="001",
                agent_name="soc-1",
                rule_group_primary=rng.choice(["pam", "syslog", "web"]),
                rule_level=rng.randint(2, 12),
                rule_id=str(5500 + rng.randint(1, 10)),
                mitre_tactics=("Initial Access", "Execution") if i % 5 == 0 else (),
                srcip="192.168.1.10",
                agent_criticality=1,
            )
        )

    # Agent 002: 110 event dengan frekuensi berbeda (burst frekuensi tinggi).
    curr_t2 = base_t + timedelta(minutes=5)
    for i in range(110):
        curr_t2 += timedelta(seconds=rng.choice([1, 2, 3]))
        stream.append(
            CanonicalRawAlert(
                wazuh_alert_id=f"a002_{i:04d}",
                timestamp=curr_t2,
                agent_id="002",
                agent_name="db-prod",
                rule_group_primary="sql_injection" if i % 10 == 0 else "syslog",
                rule_level=rng.randint(3, 15),
                rule_id=str(6000 + rng.randint(1, 5)),
                mitre_tactics=("Defense Evasion",) if i % 3 == 0 else (),
                srcip="10.0.0.50",
                agent_criticality=4,
            )
        )

    # Edge case khusus:
    # 1. Timestamp sama (gap == 0)
    same_ts = base_t + timedelta(hours=2)
    stream.append(
        CanonicalRawAlert(
            wazuh_alert_id="edge_same_ts_1",
            timestamp=same_ts,
            agent_id="001",
            agent_name="soc-1",
            rule_group_primary="pam",
            rule_level=4,
            rule_id="5501",
            mitre_tactics=(),
            srcip=None,
            agent_criticality=1,
        )
    )
    stream.append(
        CanonicalRawAlert(
            wazuh_alert_id="edge_same_ts_2",
            timestamp=same_ts,
            agent_id="001",
            agent_name="soc-1",
            rule_group_primary="pam",
            rule_level=5,
            rule_id="5502",
            mitre_tactics=(),
            srcip=None,
            agent_criticality=1,
        )
    )

    # 2. Event tepat di batas delta-t (15m) dan dekat batas 60m
    span_start = base_t + timedelta(hours=3)
    for k in range(5):  # 0, 15m, 30m, 45m, 60m
        stream.append(
            CanonicalRawAlert(
                wazuh_alert_id=f"edge_60m_{k}",
                timestamp=span_start + timedelta(minutes=k * 15),
                agent_id="001",
                agent_name="soc-1",
                rule_group_primary="attack",
                rule_level=8,
                rule_id="5710",
                mitre_tactics=("Impact",),
                srcip="203.0.113.5",
                agent_criticality=1,
            )
        )

    # 3. Event residual yang sangat terlambat (5 jam ke belakang)
    stream.append(
        CanonicalRawAlert(
            wazuh_alert_id="edge_strongly_late",
            timestamp=base_t - timedelta(hours=5),
            agent_id="001",
            agent_name="soc-1",
            rule_group_primary="pam",
            rule_level=6,
            rule_id="5501",
            mitre_tactics=(),
            srcip=None,
            agent_criticality=1,
        )
    )

    # 4. ID ingress duplikat (duplikat a001_0005)
    dup_alert = CanonicalRawAlert(
        wazuh_alert_id="a001_0005",
        timestamp=base_t + timedelta(minutes=1),
        agent_id="001",
        agent_name="soc-1",
        rule_group_primary="pam",
        rule_level=3,
        rule_id="5501",
        mitre_tactics=(),
        srcip=None,
        agent_criticality=1,
    )
    stream.append(dup_alert)

    # Acak urutan aliran agar ada kedatangan out-of-order.
    shuffled_stream = list(stream)
    rng.shuffle(shuffled_stream)

    return shuffled_stream


def run_pipeline(stream: list[CanonicalRawAlert]) -> tuple[list[MetaAlert], RBTAEngine]:
    """Jalankan pipeline streaming RBTA standar: ReorderBuffer -> RBTAEngine -> Drain."""
    buffer = LosslessReorderBuffer(capacity=50)
    engine = RBTAEngine(base_delta_t=timedelta(minutes=15), adaptive=True)
    finalized: list[MetaAlert] = []

    for alert in stream:
        ready_alerts = buffer.push(alert)
        for ready in ready_alerts:
            finalized.extend(engine.process(ready))

    for ready in buffer.drain():
        finalized.extend(engine.process(ready))

    finalized.extend(engine.drain())
    return finalized, engine


def test_full_mapping_integrity_and_event_conservation():
    """Pipeline RBTA lengkap memenuhi konservasi event 100% dan integritas pemetaan."""
    stream = generate_synthetic_stream()
    ingress_count = len(stream)
    unique_input_ids = {a.wazuh_alert_id for a in stream}
    expected_unique_count = len(unique_input_ids)
    duplicate_ingress_count = ingress_count - expected_unique_count

    # Verifikasi komposisi aliran input.
    assert ingress_count == 239
    assert duplicate_ingress_count == 1
    assert expected_unique_count == 238

    finalized_metas, engine = run_pipeline(stream)

    # Jumlah total alert tetap utuh.
    total_aggregated_count = sum(m.alert_count for m in finalized_metas)
    assert total_aggregated_count == expected_unique_count, (
        f"Event conservation failed: aggregated {total_aggregated_count} vs unique input {expected_unique_count}"
    )

    # Keanggotaan ID sumber utuh.
    all_output_source_ids = [aid for m in finalized_metas for aid in m.wazuh_alert_ids]
    output_unique_ids = set(all_output_source_ids)
    missing_ids = unique_input_ids - output_unique_ids
    duplicate_memberships = [
        aid for aid, cnt in Counter(all_output_source_ids).items() if cnt != 1
    ]

    assert len(all_output_source_ids) == expected_unique_count, "Duplicate memberships detected in MetaAlerts"
    assert output_unique_ids == unique_input_ids, "Missing or unexpected alert IDs in MetaAlerts"
    assert len(missing_ids) == 0, f"Found missing alert IDs: {missing_ids}"
    assert len(duplicate_memberships) == 0, f"Found duplicate memberships: {duplicate_memberships}"

    # Invarian durasi maksimum (0 <= durasi <= 60 menit).
    for m in finalized_metas:
        assert 0.0 <= m.duration_sec <= 3600.0, (
            f"MetaAlert {m.meta_id} duration {m.duration_sec}s outside allowed range [0, 3600]"
        )

    # Semantik single-bucket.
    for m in finalized_metas:
        assert m.rule_group_primary in {"pam", "syslog", "web", "sql_injection", "attack"}
        assert m.agent_id in {"001", "002"}

    # Isolasi state temporal per agent.
    state_001 = engine._temporal_states["001"]
    state_002 = engine._temporal_states["002"]

    assert state_001.is_warmed_up is True
    assert state_002.is_warmed_up is True
    assert state_001.baseline_gap != state_002.baseline_gap
    assert state_001.current_delta_t != state_002.current_delta_t


def test_deterministic_reproducibility_proof():
    """Aliran yang sama dijalankan dua kali lewat instance komponen baru menghasilkan output identik."""
    stream = generate_synthetic_stream()

    metas1, _ = run_pipeline(stream)
    metas2, _ = run_pipeline(stream)

    assert len(metas1) == len(metas2)
    for m1, m2 in zip(metas1, metas2):
        assert m1.meta_id == m2.meta_id
        assert m1.agent_id == m2.agent_id
        assert m1.rule_group_primary == m2.rule_group_primary
        assert m1.start_time == m2.start_time
        assert m1.end_time == m2.end_time
        assert m1.alert_count == m2.alert_count
        assert m1.max_severity == m2.max_severity
        assert m1.rule_id_distribution == m2.rule_id_distribution
        assert m1.severity_distribution == m2.severity_distribution
        assert m1.mitre_tactics_unique == m2.mitre_tactics_unique
        assert m1.critical_mitre_present == m2.critical_mitre_present
        assert m1.agent_criticality == m2.agent_criticality
        assert m1.wazuh_alert_ids == m2.wazuh_alert_ids
