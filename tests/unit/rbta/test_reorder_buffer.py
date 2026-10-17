"""Unit test LosslessReorderBuffer."""
from collections import Counter
from datetime import datetime, timedelta, timezone
import pytest

from src.contracts.raw_alert import CanonicalRawAlert
from src.rbta.reorder_buffer import LosslessReorderBuffer


def make_alert(alert_id: str, ts: datetime, agent_id: str = "001") -> CanonicalRawAlert:
    """Helper untuk membuat CanonicalRawAlert minimal yang valid."""
    return CanonicalRawAlert(
        wazuh_alert_id=alert_id,
        timestamp=ts,
        agent_id=agent_id,
        agent_name="soc-1",
        rule_group_primary="pam",
        rule_level=3,
        rule_id="5501",
        mitre_tactics=(),
        srcip=None,
        agent_criticality=1,
    )


def test_reorder_buffer_invalid_capacity():
    """Kapasitas buffer minimal 1."""
    with pytest.raises(ValueError, match="capacity"):
        LosslessReorderBuffer(capacity=0)

    with pytest.raises(ValueError, match="capacity"):
        LosslessReorderBuffer(capacity=-5)


def test_reorder_buffer_ordered_sequence():
    """Urutan input yang sudah terurut dipertahankan dan dikeluarkan tanpa kehilangan saat kapasitas penuh dan saat drain."""
    buf = LosslessReorderBuffer(capacity=3)
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)

    a1 = make_alert("1", base_t + timedelta(seconds=1))
    a2 = make_alert("2", base_t + timedelta(seconds=2))
    a3 = make_alert("3", base_t + timedelta(seconds=3))
    a4 = make_alert("4", base_t + timedelta(seconds=4))

    out = []
    out.extend(buf.push(a1))  # len 1 <= 3
    out.extend(buf.push(a2))  # len 2 <= 3
    out.extend(buf.push(a3))  # len 3 <= 3
    assert out == []

    # Push ke-4 melebihi kapasitas 3 -> keluarkan yang paling awal (a1).
    out.extend(buf.push(a4))
    assert [a.wazuh_alert_id for a in out] == ["1"]

    # Drain mengeluarkan sisanya [a2, a3, a4].
    out.extend(buf.drain())
    assert [a.wazuh_alert_id for a in out] == ["1", "2", "3", "4"]


def test_reorder_buffer_disordered_sequence():
    """Input tidak berurutan [t3, t1, t4, t2] dikeluarkan dengan urutan event-time naik yang benar."""
    buf = LosslessReorderBuffer(capacity=4)
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)

    a1 = make_alert("1", base_t + timedelta(seconds=10))
    a2 = make_alert("2", base_t + timedelta(seconds=20))
    a3 = make_alert("3", base_t + timedelta(seconds=30))
    a4 = make_alert("4", base_t + timedelta(seconds=40))

    # Push dengan urutan acak: a3, a1, a4, a2.
    out = []
    out.extend(buf.push(a3))
    out.extend(buf.push(a1))
    out.extend(buf.push(a4))
    out.extend(buf.push(a2))
    assert out == []

    out.extend(buf.drain())
    assert [a.wazuh_alert_id for a in out] == ["1", "2", "3", "4"]


def test_reorder_buffer_identical_timestamps_preserves_arrival_order():
    """Alert dengan timestamp identik mempertahankan urutan kedatangan (FIFO) yang deterministik."""
    buf = LosslessReorderBuffer(capacity=3)
    same_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)

    aA = make_alert("A", same_t)
    aB = make_alert("B", same_t)
    aC = make_alert("C", same_t)

    buf.push(aA)
    buf.push(aB)
    buf.push(aC)

    out = buf.drain()
    assert [a.wazuh_alert_id for a in out] == ["A", "B", "C"]


def test_reorder_buffer_drain_is_idempotent():
    """Drain pertama mengembalikan semua alert yang tersisa; drain berikutnya mengembalikan list kosong."""
    buf = LosslessReorderBuffer(capacity=2)
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)

    buf.push(make_alert("1", base_t))
    buf.push(make_alert("2", base_t + timedelta(seconds=1)))

    first_drain = buf.drain()
    assert len(first_drain) == 2

    second_drain = buf.drain()
    assert second_drain == []

    third_drain = buf.drain()
    assert third_drain == []


def test_reorder_buffer_conservation():
    """Setiap alert yang di-push harus keluar tepat sekali (Counter sama, tidak ada yang hilang)."""
    buf = LosslessReorderBuffer(capacity=5)
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)

    # 100 alert dengan timestamp beragam dan kedatangan tidak berurutan.
    import random
    rng = random.Random(42)
    timestamps = [base_t + timedelta(seconds=rng.randint(0, 500)) for _ in range(100)]
    alerts = [make_alert(f"id_{i}", ts) for i, ts in enumerate(timestamps)]

    emitted = []
    for a in alerts:
        emitted.extend(buf.push(a))
    emitted.extend(buf.drain())

    input_ids = [a.wazuh_alert_id for a in alerts]
    emitted_ids = [a.wazuh_alert_id for a in emitted]

    assert len(emitted_ids) == 100
    assert Counter(input_ids) == Counter(emitted_ids)


def test_reorder_buffer_late_residual_event_never_dropped():
    """Event yang sangat terlambat di dalam buffer tidak pernah dibuang dan akhirnya tetap dikeluarkan."""
    buf = LosslessReorderBuffer(capacity=2)
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)

    # Push alert normal yang lebih baru.
    a_future1 = make_alert("F1", base_t + timedelta(hours=5))
    a_future2 = make_alert("F2", base_t + timedelta(hours=6))
    # Push event terlambat yang jauh ke belakang.
    a_late = make_alert("LATE", base_t)

    out = []
    out.extend(buf.push(a_future1))
    out.extend(buf.push(a_future2))
    # Push event terlambat melebihi kapasitas 2 -> keluarkan yang paling awal (LATE).
    out.extend(buf.push(a_late))

    assert len(out) == 1
    assert out[0].wazuh_alert_id == "LATE"

    out.extend(buf.drain())
    assert [a.wazuh_alert_id for a in out] == ["LATE", "F1", "F2"]
