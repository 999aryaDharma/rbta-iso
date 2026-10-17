"""Unit test AgentTemporalState."""
from datetime import datetime, timedelta, timezone
import pytest

from src.rbta.temporal_state import AgentTemporalState, TemporalStateError


def test_first_event_initializes_state():
    """Event 1 menginisialisasi last_timestamp, mengisi hitungan warmup 1, dan mengembalikan base_delta_t."""
    base_dt = timedelta(minutes=15)
    state = AgentTemporalState(agent_id="001", base_delta_t=base_dt)

    t1 = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    dt_out = state.observe(t1)

    assert dt_out == base_dt
    assert state.warmup_event_count == 1
    assert state.last_timestamp == t1
    assert len(state.warmup_gaps) == 0
    assert state.is_warmed_up is False
    assert state.baseline_gap is None
    assert state.ema_gap is None


def test_warmup_events_1_through_99():
    """Event 1 sampai 99 mengakumulasi gap maju dan tetap mengembalikan base_delta_t."""
    base_dt = timedelta(minutes=15)
    state = AgentTemporalState(agent_id="001", base_delta_t=base_dt)

    start = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    for i in range(99):
        t = start + timedelta(seconds=i * 10)
        dt_out = state.observe(t)
        assert dt_out == base_dt
        assert state.warmup_event_count == i + 1
        assert state.is_warmed_up is False

    assert len(state.warmup_gaps) == 98
    assert all(g == 10.0 for g in state.warmup_gaps)


def test_event_100_completes_warmup_and_calculates_baseline():
    """Event 100 menyelesaikan warmup, menghitung baseline rata-rata aritmetika, menginisialisasi ema_gap, dan BELUM menerapkan EMA pasca-warmup."""
    base_dt = timedelta(minutes=15)
    state = AgentTemporalState(agent_id="001", base_delta_t=base_dt)

    start = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    # Masukkan 100 event dengan gap 10 detik (event pertama tanpa gap, 99 event berikutnya gap=10.0 detik).
    for i in range(100):
        t = start + timedelta(seconds=i * 10)
        dt_out = state.observe(t)
        assert dt_out == base_dt

    assert state.warmup_event_count == 100
    assert state.is_warmed_up is True
    assert len(state.warmup_gaps) == 99
    assert state.baseline_gap == pytest.approx(10.0)
    assert state.ema_gap == pytest.approx(10.0)
    assert state.current_delta_t == base_dt


def test_event_101_applies_first_adaptive_update_and_manual_math_verification():
    """Event 101 menerapkan EMA alpha=0.10 untuk memperbarui ema_gap dan menghitung delta_t proporsional."""
    base_dt = timedelta(minutes=10)  # 600 detik
    state = AgentTemporalState(agent_id="001", base_delta_t=base_dt)

    start = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    for i in range(100):
        t = start + timedelta(seconds=i * 10)
        state.observe(t)

    assert state.baseline_gap == pytest.approx(10.0)
    assert state.ema_gap == pytest.approx(10.0)

    # Event 101 datang setelah 5 detik.
    t_101 = start + timedelta(seconds=99 * 10 + 5)
    dt_101 = state.observe(t_101)

    # Cek manual:
    # current_gap = 5.0 detik
    # ema_gap = 0.10 * 5.0 + 0.90 * 10.0 = 0.5 + 9.0 = 9.5 detik
    # ratio = 9.5 / 10.0 = 0.95
    # candidate_delta_t = 600 detik * 0.95 = 570 detik = 9.5 menit
    assert state.ema_gap == pytest.approx(9.5)
    assert dt_101.total_seconds() == pytest.approx(570.0)
    assert state.current_delta_t == dt_101


def test_lower_and_upper_etw_clamps():
    """delta_t ETW harus dibatasi ketat ke [0.5 * base_delta_t, 1.5 * base_delta_t]."""
    base_dt = timedelta(minutes=10)  # 600 detik
    state = AgentTemporalState(agent_id="001", base_delta_t=base_dt)

    start = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    for i in range(100):
        state.observe(start + timedelta(seconds=i * 10))

    # Burst cepat: gap = 0.001 detik berulang.
    last_t = start + timedelta(seconds=990)
    for _ in range(50):
        last_t += timedelta(milliseconds=1)
        dt_out = state.observe(last_t)

    # Harus dibatasi di 0.5 * 600 = 300 detik (5 menit).
    assert dt_out.total_seconds() == pytest.approx(300.0)
    assert state.current_delta_t == timedelta(minutes=5)

    # Sepi panjang: gap = 1000 detik berulang.
    for _ in range(50):
        last_t += timedelta(seconds=1000)
        dt_out = state.observe(last_t)

    # Harus dibatasi di 1.5 * 600 = 900 detik (15 menit).
    assert dt_out.total_seconds() == pytest.approx(900.0)
    assert state.current_delta_t == timedelta(minutes=15)


def test_zero_baseline_raises_temporal_state_error():
    """Bila semua gap warmup 0 (mis. 100 event dengan timestamp identik), baseline 0 dan harus langsung gagal."""
    base_dt = timedelta(minutes=15)
    state = AgentTemporalState(agent_id="001", base_delta_t=base_dt)

    same_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    with pytest.raises(TemporalStateError, match="baseline gap is <= 0"):
        for _ in range(100):
            state.observe(same_t)


def test_invalid_warmup_baseline_becomes_terminal_and_does_not_extend_beyond_100_events():
    """Bila warmup gagal karena baseline tidak valid, state menjadi invalid permanen dan menolak event 101 ke atas."""
    base_dt = timedelta(minutes=15)
    state = AgentTemporalState(agent_id="001", base_delta_t=base_dt)

    same_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    # Event 1 sampai 100 dengan timestamp sama.
    with pytest.raises(TemporalStateError, match="baseline gap is <= 0"):
        for _ in range(100):
            state.observe(same_t)

    assert state.warmup_event_count == 100
    assert state.is_warmed_up is False
    assert state.baseline_gap is None

    # Event 101 datang dengan timestamp positif -> tetap harus gagal dan TIDAK memperpanjang warmup.
    event_101_t = same_t + timedelta(seconds=10)
    with pytest.raises(TemporalStateError, match="terminal invalid state|baseline gap is <= 0"):
        state.observe(event_101_t)

    # Invarian tetap terjaga.
    assert state.warmup_event_count == 100
    assert state.is_warmed_up is False
    assert state.baseline_gap is None


def test_retrograde_timestamp_handling():
    """Event residual out-of-order (timestamp < last_timestamp) tidak boleh memundurkan last_timestamp maupun membuat gap EMA negatif."""
    base_dt = timedelta(minutes=10)
    state = AgentTemporalState(agent_id="001", base_delta_t=base_dt)

    start = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    for i in range(100):
        state.observe(start + timedelta(seconds=i * 10))

    last_t = start + timedelta(seconds=990)
    assert state.last_timestamp == last_t
    ema_before = state.ema_gap
    dt_before = state.current_delta_t

    # Timestamp event mundur 100 detik ke belakang.
    retrograde_t = start + timedelta(seconds=500)
    dt_out = state.observe(retrograde_t)

    # last_timestamp tidak boleh mundur.
    assert state.last_timestamp == last_t
    # ema_gap dan current_delta_t tidak boleh berubah.
    assert state.ema_gap == ema_before
    assert dt_out == dt_before


def test_agent_isolation():
    """Event yang teramati di agent A tidak boleh mengubah atau memengaruhi state temporal agent B."""
    base_dt = timedelta(minutes=15)
    state_a = AgentTemporalState(agent_id="agent_A", base_delta_t=base_dt)
    state_b = AgentTemporalState(agent_id="agent_B", base_delta_t=base_dt)

    t1 = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 8, 28, 10, 0, 1, tzinfo=timezone.utc)
    t3 = datetime(2026, 8, 28, 10, 5, 0, tzinfo=timezone.utc)

    state_a.observe(t1)
    state_b.observe(t2)
    state_a.observe(t3)

    # Gap agent A harus 300 detik, tidak terpengaruh t2 milik agent B.
    assert len(state_a.warmup_gaps) == 1
    assert state_a.warmup_gaps[0] == 300.0
    assert state_a.warmup_event_count == 2
    assert state_a.last_timestamp == t3

    # State agent B tetap terisolasi.
    assert len(state_b.warmup_gaps) == 0
    assert state_b.warmup_event_count == 1
    assert state_b.last_timestamp == t2


def test_fixed_mode_never_alters_delta_t():
    """Saat adaptive=False, current_delta_t tetap base_delta_t sepanjang run."""
    base_dt = timedelta(minutes=15)
    state = AgentTemporalState(agent_id="001", base_delta_t=base_dt, adaptive=False)

    start = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    for i in range(150):
        dt_out = state.observe(start + timedelta(seconds=i * 2))
        assert dt_out == base_dt
        assert state.current_delta_t == base_dt


def test_fixed_mode_does_not_require_positive_baseline_and_supports_same_timestamps():
    """Mode tetap (adaptive=False) tidak boleh menghitung atau membutuhkan baseline adaptif, dan mendukung 150 event dengan timestamp sama."""
    base_dt = timedelta(minutes=15)
    state = AgentTemporalState(agent_id="001", base_delta_t=base_dt, adaptive=False)

    same_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    for _ in range(150):
        dt_out = state.observe(same_t)
        assert dt_out == base_dt

    assert state.current_delta_t == base_dt
    assert state.baseline_gap is None
    assert state.ema_gap is None
    assert state.warmup_event_count == 150


def test_fixed_mode_arbitrary_and_retrograde_gaps():
    """Mode tetap menangani gap sangat kecil, sangat besar, dan mundur sambil menjaga current_delta_t == base_delta_t."""
    base_dt = timedelta(minutes=15)
    state = AgentTemporalState(agent_id="001", base_delta_t=base_dt, adaptive=False)

    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    # Gap maju 1 detik.
    assert state.observe(base_t + timedelta(seconds=1)) == base_dt
    # Gap sangat besar 10 hari.
    assert state.observe(base_t + timedelta(days=10)) == base_dt
    # Gap mundur 5 hari.
    assert state.observe(base_t + timedelta(days=5)) == base_dt
    assert state.current_delta_t == base_dt
