"""Kontrak API status live yang read-only."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

from starlette.testclient import TestClient

from src.api.app import create_app
from src.runtime.durable_state import DurableStateManager
from src.runtime.service import LiveRBTAService


API_KEY = "live-status-test-key"


def _make_service(tmp_path, source_state=None):
    state_mgr = DurableStateManager(tmp_path / "state.json")
    service = LiveRBTAService(
        scoring_pipeline=MagicMock(),
        state_manager=state_mgr,
        auto_persist=False,
    )
    if source_state:
        service.source_checkpoint.update(source_state)
    return service


def _make_worker(status_dict):
    worker = SimpleNamespace()
    worker.status = lambda: dict(status_dict)
    return worker


def _client(service, worker, api_key=API_KEY):
    app = create_app(service=service, api_key=api_key)
    app.state.live_worker = worker
    return TestClient(app)


def _auth():
    return {"Authorization": f"Bearer {API_KEY}"}


def test_live_status_contract_shape(tmp_path):
    """GET /api/v1/live/status mengembalikan 200 dengan bentuk response yang sudah dikunci."""
    cursor = (datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat()
    service = _make_service(
        tmp_path,
        {"recent_poll_cursor": cursor, "live_model_version": "v-test-1"},
    )
    worker = _make_worker(
        {
            "alive": True,
            "cycles_completed": 7,
            "consecutive_failures": 0,
            "last_error": None,
            "last_cycle_at": cursor,
        }
    )
    client = _client(service, worker)
    resp = client.get("/api/v1/live/status", headers=_auth())
    assert resp.status_code == 200
    data = resp.json()
    for key in (
        "worker_alive",
        "cycles_completed",
        "consecutive_failures",
        "last_error",
        "last_cycle_at",
        "live_model_version",
        "recent_poll_cursor",
        "lag_sec",
        "buffer_size",
        "outbox_pending",
    ):
        assert key in data, f"missing key: {key}"
    assert data["worker_alive"] is True
    assert data["cycles_completed"] == 7
    assert data["consecutive_failures"] == 0
    assert data["last_error"] is None
    assert data["live_model_version"] == "v-test-1"
    assert data["recent_poll_cursor"] == cursor
    assert data["lag_sec"] is not None and data["lag_sec"] >= 0
    assert data["buffer_size"] is None  # buffer nonaktif/tidak ada berarti tidak diukur, bukan kosong
    assert data["outbox_pending"] == 0


def test_live_status_worker_none_null_safe(tmp_path):
    """Worker nonaktif (None) tetap mengembalikan 200 dengan field worker yang aman-null."""
    service = _make_service(tmp_path, {})
    client = _client(service, None)
    resp = client.get("/api/v1/live/status", headers=_auth())
    assert resp.status_code == 200
    data = resp.json()
    assert data["worker_alive"] is False
    assert data["cycles_completed"] == 0
    assert data["consecutive_failures"] == 0
    assert data["last_error"] is None
    assert data["last_cycle_at"] is None
    assert data["buffer_size"] is None  # buffer nonaktif/tidak ada berarti tidak diukur, bukan kosong
    assert data["outbox_pending"] == 0


def test_live_status_read_only(tmp_path):
    """Memanggil endpoint berulang kali tidak boleh mengubah state service."""
    cursor = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
    service = _make_service(
        tmp_path,
        {"recent_poll_cursor": cursor, "live_model_version": "v-test-1"},
    )
    worker = _make_worker(
        {
            "alive": True,
            "cycles_completed": 3,
            "consecutive_failures": 0,
            "last_error": None,
            "last_cycle_at": cursor,
        }
    )
    client = _client(service, worker)
    before_checkpoint = dict(service.source_checkpoint)
    before_history = len(service.finalized_history)
    for _ in range(5):
        resp = client.get("/api/v1/live/status", headers=_auth())
        assert resp.status_code == 200
    assert dict(service.source_checkpoint) == before_checkpoint
    assert len(service.finalized_history) == before_history


def test_live_status_lag_null_when_cursor_empty(tmp_path):
    """lag_sec bernilai null bila belum ada cursor poll."""
    service = _make_service(tmp_path, {})
    worker = _make_worker(
        {
            "alive": False,
            "cycles_completed": 0,
            "consecutive_failures": 0,
            "last_error": None,
            "last_cycle_at": None,
        }
    )
    client = _client(service, worker)
    resp = client.get("/api/v1/live/status", headers=_auth())
    assert resp.status_code == 200
    data = resp.json()
    assert data["recent_poll_cursor"] is None
    assert data["lag_sec"] is None


def test_live_status_auth_rejected_without_key(tmp_path):
    """Request tanpa key yang valid ditolak seperti endpoint lain."""
    service = _make_service(tmp_path, {})
    worker = _make_worker(
        {
            "alive": False,
            "cycles_completed": 0,
            "consecutive_failures": 0,
            "last_error": None,
            "last_cycle_at": None,
        }
    )
    client = _client(service, worker)
    resp = client.get("/api/v1/live/status")
    assert resp.status_code == 401


# Telemetri harus jujur.

def _make_buffer_worker(status_dict, held_size):
    """Worker yang coordinator-nya punya OrderBuffer aktif sebesar held_size."""
    buf = MagicMock()
    buf.status.return_value = {"size": held_size}
    coord = SimpleNamespace(order_buffer=buf)
    worker = SimpleNamespace(coordinator=coord)
    worker.status = lambda: dict(status_dict)
    return worker


def test_live_status_buffer_size_none_when_disabled(tmp_path):
    """Buffer yang tidak ada dilaporkan None (tidak diukur), bukan 0 palsu."""
    service = _make_service(tmp_path, {})
    worker = _make_worker(
        {"alive": False, "cycles_completed": 0, "consecutive_failures": 0,
         "last_error": None, "last_cycle_at": None}
    )
    assert getattr(worker, "coordinator", None) is None
    client = _client(service, worker)
    data = client.get("/api/v1/live/status", headers=_auth()).json()
    assert data["buffer_size"] is None


def test_live_status_buffer_size_reports_held_count_when_enabled(tmp_path):
    """Buffer aktif melaporkan ukuran tahanan sebenarnya lewat worker.coordinator.order_buffer."""
    service = _make_service(tmp_path, {})
    worker = _make_buffer_worker(
        {"alive": True, "cycles_completed": 1, "consecutive_failures": 0,
         "last_error": None, "last_cycle_at": None},
        held_size=4,
    )
    client = _client(service, worker)
    data = client.get("/api/v1/live/status", headers=_auth()).json()
    assert data["buffer_size"] == 4


def test_live_status_dispatcher_null_when_absent(tmp_path):
    """Tanpa dispatcher terpasang -> blok dispatcher null (getattr dijaga)."""
    service = _make_service(tmp_path, {})
    client = _client(service, _make_worker({"alive": False}))
    data = client.get("/api/v1/live/status", headers=_auth()).json()
    assert "dispatcher" in data
    assert data["dispatcher"] is None


def test_live_status_dispatcher_status_passthrough(tmp_path):
    """Dispatcher terpasang dengan .status() diteruskan; error -> null."""
    service = _make_service(tmp_path, {})
    client = _client(service, _make_worker({"alive": False}))
    client.app.state.telegram_dispatcher = SimpleNamespace(
        status=lambda: {"enabled": True, "sent": 2}
    )
    data = client.get("/api/v1/live/status", headers=_auth()).json()
    assert data["dispatcher"] == {"enabled": True, "sent": 2}

    client.app.state.telegram_dispatcher = SimpleNamespace(
        status=lambda: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    data = client.get("/api/v1/live/status", headers=_auth()).json()
    assert data["dispatcher"] is None


def test_live_status_quarantine_null_when_unsupported(tmp_path, monkeypatch):
    """state_manager tanpa quarantine_list -> quarantine_total null."""
    service = _make_service(tmp_path, {})
    monkeypatch.delattr(type(service.state_manager), "quarantine_list", raising=False)
    monkeypatch.delattr(type(service.state_manager), "quarantine_count", raising=False)
    assert not hasattr(service.state_manager, "quarantine_list")
    client = _client(service, _make_worker({"alive": False}))
    data = client.get("/api/v1/live/status", headers=_auth()).json()
    assert "quarantine_total" in data
    assert data["quarantine_total"] is None


def test_live_status_quarantine_total_when_supported(tmp_path):
    """state_manager dengan quarantine_list -> jumlah sebenarnya."""
    service = _make_service(tmp_path, {})
    service.state_manager.quarantine_count = lambda: 2
    client = _client(service, _make_worker({"alive": False}))
    data = client.get("/api/v1/live/status", headers=_auth()).json()
    assert data["quarantine_total"] == 2


def test_live_status_event_lag_null_when_no_scored_events(tmp_path):
    """History+outbox kosong -> newest_scored_event_time/event_lag_sec null."""
    service = _make_service(tmp_path, {})
    client = _client(service, _make_worker({"alive": False}))
    data = client.get("/api/v1/live/status", headers=_auth()).json()
    assert data["newest_scored_event_time"] is None
    assert data["event_lag_sec"] is None


def test_live_status_event_lag_from_history_end_time(tmp_path):
    """end_time terbaru di history/outbox menentukan event_lag_sec."""
    from types import SimpleNamespace as SN

    now = datetime.now(timezone.utc)
    service = _make_service(tmp_path, {})
    service.get_history = lambda: [
        SN(end_time=now - timedelta(minutes=10)),
        SN(end_time=now - timedelta(minutes=2)),
    ]
    service.get_outbox = lambda: [SN(end_time=now - timedelta(minutes=5))]
    client = _client(service, _make_worker({"alive": False}))
    data = client.get("/api/v1/live/status", headers=_auth()).json()
    assert data["newest_scored_event_time"] is not None
    parsed = datetime.fromisoformat(data["newest_scored_event_time"])
    assert abs((parsed - (now - timedelta(minutes=2))).total_seconds()) < 5
    assert data["event_lag_sec"] is not None
    assert 100 <= data["event_lag_sec"] <= 180


def test_live_status_last_error_redacts_host(tmp_path):
    """Host/kredensial dibuang dari last_error (scheme://host tidak bocor)."""
    service = _make_service(tmp_path, {})
    worker = _make_worker(
        {"alive": True, "cycles_completed": 1, "consecutive_failures": 1,
         "last_error": "Connection refused https://wazuh.internal:9200/wazuh-alerts/_search",
         "last_cycle_at": None}
    )
    client = _client(service, worker)
    data = client.get("/api/v1/live/status", headers=_auth()).json()
    assert data["last_error"] is not None
    assert "wazuh.internal" not in data["last_error"]
    assert "[host]" in data["last_error"]


def test_live_status_quarantine_prefers_count_over_list(tmp_path):
    """quarantine_total mengutamakan helper COUNT(*) daripada memuat baris."""
    service = _make_service(tmp_path, {})
    service.state_manager.quarantine_count = lambda: 41
    service.state_manager.quarantine_list = lambda: (_ for _ in ()).throw(
        AssertionError("list must not be loaded when count exists")
    )
    client = _client(service, _make_worker({"alive": False}))
    data = client.get("/api/v1/live/status", headers=_auth()).json()
    assert data["quarantine_total"] == 41


def test_live_status_buffer_stats_block(tmp_path):
    """Counter buffer lengkap tampil bila buffer aktif."""
    service = _make_service(tmp_path, {})
    worker = _make_worker({"alive": True})
    worker.coordinator = SimpleNamespace(
        order_buffer=SimpleNamespace(
            status=lambda: {
                "size": 3,
                "late_total": 1,
                "future_anomalies": 0,
                "backpressure_count": 2,
            }
        )
    )
    client = _client(service, worker)
    data = client.get("/api/v1/live/status", headers=_auth()).json()
    assert data["buffer_size"] == 3
    assert data["buffer_stats"] == {
        "size": 3,
        "late_total": 1,
        "future_anomalies": 0,
        "backpressure_count": 2,
    }


def test_live_status_buffer_stats_null_when_disabled(tmp_path):
    """buffer_stats null (bukan nol) bila buffer nonaktif."""
    service = _make_service(tmp_path, {})
    client = _client(service, _make_worker({"alive": False}))
    data = client.get("/api/v1/live/status", headers=_auth()).json()
    assert data["buffer_size"] is None
    assert data["buffer_stats"] is None


def test_live_status_event_lag_from_ingested_time(tmp_path):
    """event_lag_sec diukur dari event terbaru yang di-ingest, bukan dari flush skor."""
    now = datetime.now(timezone.utc)
    service = _make_service(
        tmp_path,
        {"newest_ingested_event_time": (now - timedelta(seconds=45)).isoformat()},
    )
    client = _client(service, _make_worker({"alive": True}))
    data = client.get("/api/v1/live/status", headers=_auth()).json()
    assert data["newest_ingested_event_time"] is not None
    assert 30 <= data["event_lag_sec"] <= 120


def test_live_status_tls_verify_passthrough(tmp_path):
    """Pilihan operator tls_verify terlihat di status."""
    service = _make_service(tmp_path, {"tls_verify": False})
    client = _client(service, _make_worker({"alive": False}))
    data = client.get("/api/v1/live/status", headers=_auth()).json()
    assert data["tls_verify"] is False


def test_live_status_ingested_total_counts_seen_ids(tmp_path):
    """ingested_total menampilkan jumlah alert unik yang durable."""
    service = _make_service(tmp_path, {})
    service.state_manager.count_seen_alert_ids = lambda: 1899
    client = _client(service, _make_worker({"alive": True}))
    data = client.get("/api/v1/live/status", headers=_auth()).json()
    assert data["ingested_total"] == 1899


def test_live_status_ingested_total_null_when_unsupported(tmp_path, monkeypatch):
    """ingested_total null (bukan 0) bila counter tidak tersedia."""
    service = _make_service(tmp_path, {})
    monkeypatch.delattr(type(service.state_manager), "count_seen_alert_ids", raising=False)
    client = _client(service, _make_worker({"alive": False}))
    data = client.get("/api/v1/live/status", headers=_auth()).json()
    assert data["ingested_total"] is None
