"""Unit test RBTAEngine single-bucket yang deterministik."""
from datetime import datetime, timedelta, timezone
import pytest

from src.contracts.meta_alert import MetaAlert
from src.contracts.raw_alert import CanonicalRawAlert
from src.rbta.engine import RBTAEngine, RBTAInvariantError


def make_alert(
    alert_id: str,
    ts: datetime,
    agent_id: str = "001",
    agent_name: str = "soc-1",
    group: str = "pam",
    level: int = 3,
    rule_id: str = "5501",
    mitre: tuple[str, ...] = (),
    crit: int = 1,
) -> CanonicalRawAlert:
    """Helper untuk membuat CanonicalRawAlert dengan field tertentu."""
    return CanonicalRawAlert(
        wazuh_alert_id=alert_id,
        timestamp=ts,
        agent_id=agent_id,
        agent_name=agent_name,
        rule_group_primary=group,
        rule_level=level,
        rule_id=rule_id,
        mitre_tactics=mitre,
        srcip="192.168.1.50",
        agent_criticality=crit,
    )


# Kunci bucket

def test_same_agent_same_group_aggregates_into_same_bucket():
    """Alert dari agent dan rule group yang sama dalam delta_t digabung ke satu bucket."""
    engine = RBTAEngine(base_delta_t=timedelta(minutes=15))
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)

    a1 = make_alert("1", base_t, agent_id="001", group="pam")
    a2 = make_alert("2", base_t + timedelta(minutes=5), agent_id="001", group="pam")

    out1 = engine.process(a1)
    out2 = engine.process(a2)
    assert out1 == []
    assert out2 == []

    meta_list = engine.drain()
    assert len(meta_list) == 1
    meta = meta_list[0]
    assert meta.agent_id == "001"
    assert meta.rule_group_primary == "pam"
    assert meta.alert_count == 2
    assert meta.wazuh_alert_ids == ("1", "2")


def test_same_agent_different_group_creates_different_buckets():
    """Alert dari agent sama tetapi rule group berbeda membentuk bucket aktif terpisah."""
    engine = RBTAEngine(base_delta_t=timedelta(minutes=15))
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)

    a1 = make_alert("1", base_t, agent_id="001", group="pam")
    a2 = make_alert("2", base_t + timedelta(minutes=2), agent_id="001", group="syslog")

    engine.process(a1)
    engine.process(a2)

    meta_list = engine.drain()
    assert len(meta_list) == 2
    groups = {m.rule_group_primary for m in meta_list}
    assert groups == {"pam", "syslog"}


def test_different_agent_same_group_creates_different_buckets():
    """Alert dari agent berbeda dengan rule group sama membentuk bucket aktif terpisah."""
    engine = RBTAEngine(base_delta_t=timedelta(minutes=15))
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)

    a1 = make_alert("1", base_t, agent_id="001", group="pam")
    a2 = make_alert("2", base_t + timedelta(minutes=2), agent_id="002", group="pam")

    engine.process(a1)
    engine.process(a2)

    meta_list = engine.drain()
    assert len(meta_list) == 2
    agent_ids = {m.agent_id for m in meta_list}
    assert agent_ids == {"001", "002"}


# Semantik batas merge / split

def test_gap_equal_to_delta_t_merges():
    """Batas inklusif: gap == delta_t HARUS di-merge."""
    base_dt = timedelta(minutes=10)
    engine = RBTAEngine(base_delta_t=base_dt)
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)

    a1 = make_alert("1", base_t)
    # Gap tepat 10 menit.
    a2 = make_alert("2", base_t + timedelta(minutes=10))

    out1 = engine.process(a1)
    out2 = engine.process(a2)
    assert out1 == []
    assert out2 == []

    meta_list = engine.drain()
    assert len(meta_list) == 1
    assert meta_list[0].alert_count == 2


def test_gap_greater_than_delta_t_splits():
    """gap > delta_t HARUS split (finalkan bucket sebelumnya dan buat yang baru)."""
    base_dt = timedelta(minutes=10)
    engine = RBTAEngine(base_delta_t=base_dt)
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)

    a1 = make_alert("1", base_t)
    # 10 menit + 1 detik -> split.
    a2 = make_alert("2", base_t + timedelta(minutes=10, seconds=1))

    out1 = engine.process(a1)
    assert out1 == []
    out2 = engine.process(a2)
    assert len(out2) == 1
    assert out2[0].wazuh_alert_ids == ("1",)

    meta_list = engine.drain()
    assert len(meta_list) == 1
    assert meta_list[0].wazuh_alert_ids == ("2",)


def test_max_duration_60_minutes_boundary():
    """Durasi prospektif <= 60 menit di-merge; durasi > 60 menit di-split."""
    engine = RBTAEngine(base_delta_t=timedelta(minutes=15))
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)

    # Alert datang setiap 15 menit (gap == delta_t).
    a1 = make_alert("1", base_t)
    a2 = make_alert("2", base_t + timedelta(minutes=15))
    a3 = make_alert("3", base_t + timedelta(minutes=30))
    a4 = make_alert("4", base_t + timedelta(minutes=45))
    # Tepat 60 menit dari start_time -> durasi == 60m (masih boleh).
    a5 = make_alert("5", base_t + timedelta(minutes=60))

    assert engine.process(a1) == []
    assert engine.process(a2) == []
    assert engine.process(a3) == []
    assert engine.process(a4) == []
    out5 = engine.process(a5)
    assert out5 == []

    # 60m + 1 detik (gap 1 detik <= 15m, tetapi durasi prospektif > 60m) -> split.
    a6 = make_alert("6", base_t + timedelta(minutes=60, seconds=1))
    out6 = engine.process(a6)
    assert len(out6) == 1
    assert out6[0].alert_count == 5
    assert out6[0].duration_sec == 3600.0
    assert out6[0].wazuh_alert_ids == ("1", "2", "3", "4", "5")

    drained = engine.drain()
    assert len(drained) == 1
    assert drained[0].wazuh_alert_ids == ("6",)


# Semantik residual out-of-order

def test_earlier_residual_event_within_delta_t_expands_start_time():
    """Event yang lebih awal tetapi masih dalam delta_t dari bucket.start_time memperluas start_time dengan aman."""
    engine = RBTAEngine(base_delta_t=timedelta(minutes=10))
    base_t = datetime(2026, 8, 28, 10, 10, 0, tzinfo=timezone.utc)

    a1 = make_alert("1", base_t)
    engine.process(a1)

    # a0 datang dengan timestamp 5 menit lebih awal dari start_time.
    a0 = make_alert("0", base_t - timedelta(minutes=5))
    out0 = engine.process(a0)
    assert out0 == []

    meta_list = engine.drain()
    assert len(meta_list) == 1
    meta = meta_list[0]
    assert meta.alert_count == 2
    assert meta.start_time == base_t - timedelta(minutes=5)
    assert meta.end_time == base_t
    assert meta.duration_sec == 300.0


def test_extremely_late_non_mergeable_event_creates_immediate_singleton():
    """Event yang sangat terlambat dan tidak bisa di-merge langsung menjadi singleton tanpa merusak bucket aktif."""
    engine = RBTAEngine(base_delta_t=timedelta(minutes=10))
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)

    # Bucket aktif pukul 10:00.
    a1 = make_alert("1", base_t)
    engine.process(a1)

    # Event terlambat 5 jam ke belakang.
    a_late = make_alert("LATE", base_t - timedelta(hours=5))
    out_late = engine.process(a_late)

    # Singleton yang langsung difinalkan.
    assert len(out_late) == 1
    assert out_late[0].wazuh_alert_ids == ("LATE",)
    assert out_late[0].alert_count == 1

    # Bucket aktif a1 tetap utuh.
    drained = engine.drain()
    assert len(drained) == 1
    assert drained[0].wazuh_alert_ids == ("1",)


# Kebenaran agregasi & field

def test_aggregation_distributions_max_severity_and_mitre():
    """Engine harus mengakumulasi distribusi, severity maksimum, taktik MITRE tanpa membedakan huruf, dan flag kritis."""
    engine = RBTAEngine(base_delta_t=timedelta(minutes=15))
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)

    a1 = make_alert("1", base_t, level=3, rule_id="5501", mitre=("Execution",))
    a2 = make_alert("2", base_t + timedelta(minutes=2), level=7, rule_id="5502", mitre=("execution", "Initial Access"))
    a3 = make_alert("3", base_t + timedelta(minutes=4), level=5, rule_id="5501", mitre=("Defense Evasion",))

    engine.process(a1)
    engine.process(a2)
    engine.process(a3)

    meta = engine.drain()[0]
    assert meta.alert_count == 3
    assert meta.max_severity == 7
    assert meta.rule_id_distribution == {"5501": 2, "5502": 1}
    assert meta.severity_distribution == {3: 1, 7: 1, 5: 1}
    assert meta.mitre_tactics_unique == ("Execution", "Initial Access", "Defense Evasion")
    assert meta.critical_mitre_present is True


def test_contradictory_agent_criticality_raises_error():
    """agent_criticality yang bertentangan untuk agent/bucket yang sama harus langsung gagal."""
    engine = RBTAEngine(base_delta_t=timedelta(minutes=15))
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)

    a1 = make_alert("1", base_t, agent_id="001", crit=1)
    a2 = make_alert("2", base_t + timedelta(minutes=2), agent_id="001", crit=3)

    engine.process(a1)
    with pytest.raises(RBTAInvariantError, match="Contradictory agent_criticality"):
        engine.process(a2)


def test_failed_process_does_not_poison_seen_id_and_can_be_retried():
    """process() yang gagal harus atomik: tidak ada mutasi state, ID tidak ditandai seen, dan bisa dicoba ulang."""
    engine = RBTAEngine(base_delta_t=timedelta(minutes=15))
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)

    # Proses alert A dengan sukses.
    alert_a = make_alert("alert_A", base_t, agent_id="001", crit=1)
    engine.process(alert_a)

    # Snapshot state sebelum kegagalan.
    seen_before = set(engine._seen_alert_ids)
    temp_state = engine._temporal_states["001"]
    warmup_count_before = temp_state.warmup_event_count
    last_t_before = temp_state.last_timestamp
    warmup_gaps_before = list(temp_state.warmup_gaps)
    meta_counter_before = engine._meta_id_counter

    active_bucket = engine._active_buckets[("001", "pam")]
    bucket_count_before = active_bucket.alert_count
    bucket_ids_before = list(active_bucket.wazuh_alert_ids)

    # Proses alert B dengan kritikalitas bertentangan -> harus melempar RBTAInvariantError.
    bad_alert_b = make_alert("alert_B", base_t + timedelta(minutes=2), agent_id="001", crit=3)
    with pytest.raises(RBTAInvariantError, match="Contradictory agent_criticality"):
        engine.process(bad_alert_b)

    # Tidak ada mutasi yang teramati akibat alert_B yang gagal.
    assert "alert_B" not in engine._seen_alert_ids
    assert engine._seen_alert_ids == seen_before

    assert temp_state.warmup_event_count == warmup_count_before
    assert temp_state.last_timestamp == last_t_before
    assert temp_state.warmup_gaps == warmup_gaps_before
    assert engine._meta_id_counter == meta_counter_before

    assert active_bucket.alert_count == bucket_count_before
    assert active_bucket.wazuh_alert_ids == bucket_ids_before

    # Coba ulang alert B yang sudah dikoreksi (crit=1 yang cocok).
    corrected_alert_b = make_alert("alert_B", base_t + timedelta(minutes=2), agent_id="001", crit=1)
    out_b = engine.process(corrected_alert_b)
    assert out_b == []

    # Retry berhasil dan memutasi tepat satu kali.
    assert "alert_B" in engine._seen_alert_ids
    current_temp_state = engine._temporal_states["001"]
    assert current_temp_state.warmup_event_count == warmup_count_before + 1
    assert current_temp_state.last_timestamp == base_t + timedelta(minutes=2)
    current_active_bucket = engine._active_buckets[("001", "pam")]
    assert current_active_bucket.alert_count == 2
    assert current_active_bucket.wazuh_alert_ids == ["alert_A", "alert_B"]


def test_fixed_mode_engine_aggregates_without_adaptive_baseline_dependency():
    """RBTAEngine mode tetap (adaptive=False) mengagregasi dengan benar tanpa butuh baseline adaptif."""
    engine = RBTAEngine(base_delta_t=timedelta(minutes=15), adaptive=False)
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)

    # Masukkan 150 event dengan timestamp identik.
    for i in range(150):
        alert = make_alert(f"same_{i}", base_t, agent_id="001", group="pam")
        engine.process(alert)

    drained = engine.drain()
    assert len(drained) == 1
    assert drained[0].alert_count == 150
    assert drained[0].duration_sec == 0.0


# Idempotensi

def test_duplicate_wazuh_alert_id_is_idempotent_no_op():
    """Ingress duplikat dengan wazuh_alert_id identik tidak boleh menambah mutasi apa pun."""
    engine = RBTAEngine(base_delta_t=timedelta(minutes=15))
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)

    a1 = make_alert("dup-1", base_t)
    out1 = engine.process(a1)
    assert out1 == []

    # Proses alert yang persis sama sekali lagi.
    out_dup = engine.process(a1)
    assert out_dup == []

    meta_list = engine.drain()
    assert len(meta_list) == 1
    assert meta_list[0].alert_count == 1
    assert meta_list[0].wazuh_alert_ids == ("dup-1",)


# Flush idle

def test_flush_idle_strict_greater_than_delta_t():
    """flush_idle hanya memfinalkan saat idle_gap > current_delta_t (bukan saat idle_gap == current_delta_t)."""
    base_dt = timedelta(minutes=10)
    engine = RBTAEngine(base_delta_t=base_dt)
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)

    a1 = make_alert("1", base_t)
    engine.process(a1)

    # Idle tepat 10 menit -> idle_gap == delta_t -> masih boleh merge -> JANGAN flush.
    flush_exact = engine.flush_idle(base_t + timedelta(minutes=10))
    assert flush_exact == []

    # Idle 10 menit + 1 detik -> idle_gap > delta_t -> flush.
    flush_over = engine.flush_idle(base_t + timedelta(minutes=10, seconds=1))
    assert len(flush_over) == 1
    assert flush_over[0].wazuh_alert_ids == ("1",)

    # Flush berikutnya mengembalikan list kosong.
    assert engine.flush_idle(base_t + timedelta(minutes=20)) == []


# Drain dan determinisme

def test_drain_is_idempotent():
    """drain() memfinalkan semua bucket aktif dan membersihkan state; drain berikutnya mengembalikan list kosong."""
    engine = RBTAEngine(base_delta_t=timedelta(minutes=15))
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)

    engine.process(make_alert("1", base_t))
    engine.process(make_alert("2", base_t, group="syslog"))

    d1 = engine.drain()
    assert len(d1) == 2

    d2 = engine.drain()
    assert d2 == []


def test_deterministic_meta_ids_and_repeated_runs():
    """Urutan input identik lewat engine baru menghasilkan objek MetaAlert dan ID yang identik."""
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    alerts = [
        make_alert("1", base_t, group="pam"),
        make_alert("2", base_t + timedelta(minutes=5), group="pam"),
        make_alert("3", base_t + timedelta(minutes=30), group="pam"),
        make_alert("4", base_t + timedelta(minutes=2), group="syslog"),
    ]

    engine1 = RBTAEngine(base_delta_t=timedelta(minutes=15))
    out1 = []
    for a in alerts:
        out1.extend(engine1.process(a))
    out1.extend(engine1.drain())

    engine2 = RBTAEngine(base_delta_t=timedelta(minutes=15))
    out2 = []
    for a in alerts:
        out2.extend(engine2.process(a))
    out2.extend(engine2.drain())

    assert len(out1) == len(out2)
    for m1, m2 in zip(out1, out2):
        assert m1.meta_id == m2.meta_id
        assert m1.agent_id == m2.agent_id
        assert m1.rule_group_primary == m2.rule_group_primary
        assert m1.alert_count == m2.alert_count
        assert m1.wazuh_alert_ids == m2.wazuh_alert_ids


def test_engine_public_seen_accessors():
    """Property seen_alert_count dan accessor has_seen_alert bekerja dengan benar."""
    engine = RBTAEngine(base_delta_t=timedelta(minutes=15))
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)

    assert engine.seen_alert_count == 0
    assert not engine.has_seen_alert("alt-1")

    engine.process(make_alert("alt-1", base_t, group="pam"))
    assert engine.seen_alert_count == 1
    assert engine.has_seen_alert("alt-1")
    assert not engine.has_seen_alert("alt-2")

    # Alert duplikat bersifat idempoten dan tidak menambah jumlah seen.
    engine.process(make_alert("alt-1", base_t + timedelta(minutes=1), group="pam"))
    assert engine.seen_alert_count == 1

    engine.process(make_alert("alt-2", base_t + timedelta(minutes=2), group="syslog"))
    assert engine.seen_alert_count == 2
    assert engine.has_seen_alert("alt-2")
