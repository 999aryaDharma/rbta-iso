"""Persistensi state runtime yang durable dan pemulihan setelah crash."""

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import logging
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from src.contracts.raw_alert import CanonicalRawAlert
from src.rbta.engine import RBTAEngine, _ActiveBucket
from src.rbta.temporal_state import AgentTemporalState

logger = logging.getLogger(__name__)

# Versi logika derivasi canonicalizer Wazuh yang dicakup :func:`compute_derivation_hash`.
# Naikkan bila semantik canonicalizer berubah, supaya deteksi drift gagal secara
# tertutup alih-alih diam-diam memakai state lama.
CANONICALIZER_VERSION = "1.0"


def compute_derivation_hash() -> str:
    """Hitung hash stabil dari konfigurasi derivasi canonicalizer.

    Canonicalizer menurunkan ``agent_criticality`` dan ``rule_group_primary`` dari tabel
    domain di :mod:`src.config.domain`; perubahan apa pun pada tabel itu diam-diam mengubah
    fingerprint, bucket, dan fitur. Hash dari representasi JSON terurutnya (ditambah
    :data:`CANONICALIZER_VERSION`) membuat live worker bisa mendeteksi drift konfigurasi
    terhadap hash yang disimpan bersama state durable (selalu terlihat, tidak pernah diam).

    Gagal tertutup seperti pinning model: bila konfigurasi tidak bisa dibaca, error
    diteruskan — sengaja tidak ada fallback konstanta, agar konfigurasi rusak tidak
    pernah menyamar sebagai derivasi yang sudah benar.
    """
    from src.config.domain import (
        AGENT_CRITICALITY,
        CRITICAL_MITRE_TACTICS,
        DEFAULT_AGENT_CRITICALITY,
        DEFAULT_RULE_GROUP_WEIGHT,
        GROUP_SEVERITY_WEIGHT,
    )

    derivation = {
        "agent_criticality": dict(sorted(AGENT_CRITICALITY.items())),
        "group_severity_weight": dict(sorted(GROUP_SEVERITY_WEIGHT.items())),
        "critical_mitre_tactics": sorted(str(t) for t in CRITICAL_MITRE_TACTICS),
        "default_agent_criticality": DEFAULT_AGENT_CRITICALITY,
        "default_rule_group_weight": DEFAULT_RULE_GROUP_WEIGHT,
        "canonicalizer_version": CANONICALIZER_VERSION,
    }
    canonical = json.dumps(derivation, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class DurableStateManager:
    """Mengelola serialisasi state durable dan pemulihan crash untuk RBTAEngine dan runtime."""

    def __init__(self, filepath: Union[str, Path] = "state/runtime_state.json", finalized_history_db_path: Optional[Union[str, Path]] = None) -> None:
        self.filepath: Path = Path(filepath).resolve()
        self.history_db_path: Path = Path(finalized_history_db_path).resolve() if finalized_history_db_path else self.filepath.with_name("finalized_history.sqlite3")
        self._init_db()

    def _init_db(self):
        self.history_db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.history_db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS finalized_history (
                    meta_id INTEGER PRIMARY KEY,
                    scored_data TEXT NOT NULL,
                    inserted_at TEXT NOT NULL DEFAULT (datetime('now'))
                )
                """
            )
            # Migrasi aditif (T7) untuk DB lama: kolom latensi, NULL untuk baris sebelum migrasi.
            self._ensure_column(conn, "finalized_history", "finalized_at", "TEXT")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS seen_alert_ids (
                    wazuh_alert_id TEXT PRIMARY KEY,
                    inserted_at TEXT NOT NULL DEFAULT (datetime('now'))
                )
                """
            )
            conn.execute("CREATE TABLE IF NOT EXISTS runtime_snapshot (id INTEGER PRIMARY KEY CHECK (id = 1), payload TEXT NOT NULL)")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS quarantined_alerts (
                    wazuh_alert_id TEXT PRIMARY KEY,
                    source_index TEXT NOT NULL DEFAULT '',
                    source_document_id TEXT NOT NULL DEFAULT '',
                    error_type TEXT NOT NULL DEFAULT '',
                    count INTEGER NOT NULL DEFAULT 1,
                    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
                    last_seen TEXT NOT NULL DEFAULT (datetime('now'))
                )
                """
            )
            conn.execute("CREATE TABLE IF NOT EXISTS derivation_state (id INTEGER PRIMARY KEY CHECK (id = 1), derivation_hash TEXT NOT NULL)")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS suppressed_notifications (
                    meta_id INTEGER PRIMARY KEY,
                    reason TEXT NOT NULL DEFAULT '',
                    suppressed_at TEXT NOT NULL DEFAULT (datetime('now'))
                )
                """
            )
            # Alert dari agen yang dikecualikan (RBTA_EXCLUDED_AGENTS): tidak pernah masuk seen,
            # evidence, maupun RBTA. Dicatat per ID agar poll ulang tidak menggandakan counter.
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS excluded_alerts (
                    wazuh_alert_id TEXT PRIMARY KEY,
                    agent TEXT NOT NULL,
                    excluded_at TEXT NOT NULL DEFAULT (datetime('now'))
                )
                """
            )
            self._ensure_column(conn, "excluded_alerts", "event_time", "TEXT")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS notification_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    meta_id INTEGER,
                    run_id TEXT,
                    verdict TEXT,
                    at TEXT NOT NULL DEFAULT (datetime('now'))
                )
                """
            )
            self._ensure_column(conn, "notification_log", "sent_at", "TEXT")
            # Label analyst (T8). Satu label terbaru per MetaAlert; history label tidak disimpan.
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS analyst_verdict (
                    meta_id INTEGER PRIMARY KEY,
                    verdict TEXT NOT NULL CHECK (verdict IN ('incident', 'actionable_benign', 'noise')),
                    note TEXT NOT NULL DEFAULT '',
                    labeled_by TEXT NOT NULL DEFAULT '',
                    labeled_at TEXT NOT NULL
                )
                """
            )

    @staticmethod
    def _ensure_column(conn: sqlite3.Connection, table: str, column: str, decl: str) -> None:
        """ALTER TABLE ADD COLUMN bila kolom belum ada (idempoten, aman untuk DB yang sudah berisi)."""
        existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
        if column not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")

    def _assert_no_finalized_collision(self, new_finalized_history: List[Dict[str, Any]]) -> None:
        """Gagal tertutup bila meta_id dalam batch sudah ada di finalized_history.

        Mengabaikan diam-diam (INSERT OR IGNORE) akan membuat aliran meta_id bercabang —
        baris batch terbuang sementara counter di memori sudah maju. Dicek dengan SELECT
        read-only (per 500) sebelum ada penulisan, sehingga commit tetap hanya terjadi saat berhasil.

        Idempotensi: baris yang bertabrakan tetapi scored_data-nya identik dengan item batch
        adalah checkpoint yang di-retry, bukan cabang — lolos tanpa error. Isi yang berbeda di
        bawah meta_id yang sudah di-commit tetap memicu error.
        """
        ids = [int(item["meta_id"]) for item in (new_finalized_history or [])]
        if not ids:
            return
        batch_by_id: Dict[int, Dict[str, Any]] = {}
        for item in (new_finalized_history or []):
            batch_by_id.setdefault(int(item["meta_id"]), item)
        with sqlite3.connect(self.history_db_path) as conn:
            for start in range(0, len(ids), 500):
                chunk = ids[start:start + 500]
                placeholders = ",".join("?" for _ in chunk)
                rows = conn.execute(
                    f"SELECT meta_id, scored_data FROM finalized_history WHERE meta_id IN ({placeholders})",
                    chunk,
                ).fetchall()
                if not rows:
                    continue
                divergent = sorted(
                    int(r[0]) for r in rows
                    if json.loads(r[1]) != batch_by_id.get(int(r[0]))
                )
                if divergent:
                    raise RuntimeError(
                        f"Refusing to checkpoint: batch meta_id(s) already committed "
                        f"in finalized_history with divergent content: {divergent}"
                    )
    def append_finalized(self, scored_items: List[Dict[str, Any]]) -> None:
        if not scored_items:
            return
        
        batch = [
            (item["meta_id"], json.dumps(item))
            for item in scored_items
        ]
        
        with sqlite3.connect(self.history_db_path) as conn:
            conn.executemany(
                """
                INSERT OR IGNORE INTO finalized_history (meta_id, scored_data)
                VALUES (?, ?)
                """,
                batch
            )

    def load_finalized_history(self, limit: int = 1000) -> List[Dict[str, Any]]:
        if not self.history_db_path.exists():
            return []
        with sqlite3.connect(self.history_db_path) as conn:
            cursor = conn.execute(
                "SELECT scored_data FROM (SELECT meta_id, scored_data FROM finalized_history ORDER BY meta_id DESC LIMIT ?) ORDER BY meta_id ASC",
                (max(1, int(limit)),),
            )
            rows = cursor.fetchall()
        return [json.loads(row[0]) for row in rows]

    @staticmethod
    def _scope_where(agent_id=None, rule_group_primary=None, start=None, end=None):
        """Klausa WHERE untuk filter lingkup dashboard; end_time disimpan sebagai ISO UTC."""
        def iso(dt: datetime) -> str:
            return (dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).isoformat()

        clauses, params = [], []
        for field, value in (("agent_id", agent_id), ("rule_group_primary", rule_group_primary)):
            if value:
                clauses.append(f"json_extract(scored_data, '$.{field}') = ?")
                params.append(value)
        if start:
            clauses.append("json_extract(scored_data, '$.end_time') >= ?")
            params.append(iso(start))
        if end:
            clauses.append("json_extract(scored_data, '$.end_time') <= ?")
            params.append(iso(end))
        return (" WHERE " + " AND ".join(clauses)) if clauses else "", params

    def finalized_filter_options(self) -> Dict[str, Any]:
        """Agen dan rule group yang pernah muncul di history (untuk pilihan filter)."""
        if not self.history_db_path.exists():
            return {"agents": [], "rule_groups": []}
        with sqlite3.connect(self.history_db_path) as conn:
            agents = conn.execute(
                "SELECT json_extract(scored_data, '$.agent_id'), MAX(json_extract(scored_data, '$.agent_name'))"
                " FROM finalized_history GROUP BY 1 ORDER BY 1"
            ).fetchall()
            groups = conn.execute(
                "SELECT DISTINCT json_extract(scored_data, '$.rule_group_primary') FROM finalized_history ORDER BY 1"
            ).fetchall()
        return {
            "agents": [{"agent_id": a, "agent_name": n or a} for a, n in agents if a],
            "rule_groups": [g[0] for g in groups if g[0]],
        }

    def summarize_finalized(self, **scope: Any) -> Dict[str, int]:
        """Hitung KPI dari seluruh history SQLite (bukan cache memori yang dipotong)."""
        keys = ("meta_count", "escalate", "digest", "suppress", "critical", "anomalies")
        if not self.history_db_path.exists():
            return dict.fromkeys(keys, 0)
        where, params = self._scope_where(**scope)
        with sqlite3.connect(self.history_db_path) as conn:
            row = conn.execute(
                """
                SELECT COUNT(*),
                  COALESCE(SUM(json_extract(scored_data, '$.action') = 'ESCALATE'), 0),
                  COALESCE(SUM(json_extract(scored_data, '$.action') = 'DAILY_DIGEST'), 0),
                  COALESCE(SUM(json_extract(scored_data, '$.action') = 'SUPPRESS'), 0),
                  COALESCE(SUM(json_extract(scored_data, '$.decision') = 'CRITICAL'), 0),
                  COALESCE(SUM(CAST(json_extract(scored_data, '$.anomaly_score') AS REAL)
                      >= CAST(json_extract(scored_data, '$.threshold_used') AS REAL)), 0)
                FROM finalized_history""" + where,
                params,
            ).fetchone()
        return dict(zip(keys, (int(v) for v in row)))

    def count_finalized(self) -> int:
        if not self.history_db_path.exists():
            return 0
        with sqlite3.connect(self.history_db_path) as conn:
            return int(conn.execute("SELECT COUNT(*) FROM finalized_history").fetchone()[0])

    def latest_finalized_meta_id(self, agent_id: str, rule_group_primary: str) -> Optional[int]:
        """meta_id final terbaru untuk bucket key ini, dari seluruh history SQLite."""
        if not self.history_db_path.exists():
            return None
        with sqlite3.connect(self.history_db_path) as conn:
            row = conn.execute(
                "SELECT meta_id FROM finalized_history"
                " WHERE json_extract(scored_data, '$.agent_id') = ?"
                " AND json_extract(scored_data, '$.rule_group_primary') = ?"
                " ORDER BY meta_id DESC LIMIT 1",
                (agent_id, rule_group_primary),
            ).fetchone()
        return int(row[0]) if row else None

    def count_finalized_by_hour(self, **scope: Any) -> Dict[str, int]:
        """Jumlah MetaAlert final per jam (kunci 'YYYY-MM-DD HH:00') dari end_time."""
        if not self.history_db_path.exists():
            return {}
        where, params = self._scope_where(**scope)
        with sqlite3.connect(self.history_db_path) as conn:
            rows = conn.execute(
                "SELECT substr(json_extract(scored_data, '$.end_time'), 1, 13), COUNT(*) "
                "FROM finalized_history" + where + " GROUP BY 1",
                params,
            ).fetchall()
        return {f"{h.replace('T', ' ')}:00": int(n) for h, n in rows if h}

    def get_finalized(self, meta_id: int) -> Optional[Dict[str, Any]]:
        with sqlite3.connect(self.history_db_path) as conn:
            row = conn.execute(
                "SELECT scored_data FROM finalized_history WHERE meta_id = ?", (int(meta_id),)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def query_finalized(
        self,
        *,
        page: int = 1,
        page_size: int = 20,
        decision: Optional[str] = None,
        action: Optional[str] = None,
        agent_id: Optional[str] = None,
        rule_group_primary: Optional[str] = None,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        search: Optional[str] = None,
        sort_by: str = "end_time",
        sort_order: str = "desc",
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Query history append-only di SQLite tanpa memuatnya ke RAM."""
        sort_expressions = {
            "meta_id": "meta_id",
            "start_time": "json_extract(scored_data, '$.start_time')",
            "end_time": "json_extract(scored_data, '$.end_time')",
            "alert_count": "CAST(json_extract(scored_data, '$.alert_count') AS INTEGER)",
            "max_severity": "CAST(json_extract(scored_data, '$.max_severity') AS INTEGER)",
            "anomaly_score": "CAST(json_extract(scored_data, '$.anomaly_score') AS REAL)",
        }
        order_expr = sort_expressions.get(sort_by, sort_expressions["end_time"])
        direction = "ASC" if sort_order.lower() == "asc" else "DESC"
        clauses: List[str] = []
        params: List[Any] = []
        for field, value in (("decision", decision), ("action", action)):
            if value:
                clauses.append(f"json_extract(scored_data, '$.{field}') = ?")
                params.append(value)
        scope_where, scope_params = self._scope_where(agent_id, rule_group_primary, start, end)
        if scope_where:
            clauses.append(scope_where[len(" WHERE "):])
            params.extend(scope_params)
        if search and search.strip():
            clauses.append("(CAST(meta_id AS TEXT) LIKE ? OR lower(json_extract(scored_data, '$.rule_group_primary')) LIKE ? OR lower(json_extract(scored_data, '$.agent_name')) LIKE ? OR lower(json_extract(scored_data, '$.agent_id')) LIKE ?)")
            needle = f"%{search.strip().lower()}%"
            params.extend([needle] * 4)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        offset = (max(1, page) - 1) * max(1, page_size)
        with sqlite3.connect(self.history_db_path) as conn:
            total_row = conn.execute(f"SELECT COUNT(*) FROM finalized_history{where}", params).fetchone()
            rows = conn.execute(
                f"SELECT scored_data FROM finalized_history{where} ORDER BY {order_expr} {direction} LIMIT ? OFFSET ?",
                [*params, max(1, page_size), offset],
            ).fetchall()
        return [json.loads(row[0]) for row in rows], int(total_row[0]) if total_row else 0

    def append_seen_alert_ids(self, alert_ids: Set[str]) -> None:
        """Simpan hanya ID yang di-commit sejak checkpoint sebelumnya."""
        if not alert_ids:
            return
        with sqlite3.connect(self.history_db_path) as conn:
            conn.executemany(
                "INSERT OR IGNORE INTO seen_alert_ids (wazuh_alert_id) VALUES (?)",
                ((alert_id,) for alert_id in alert_ids),
            )

    def load_seen_alert_ids(self) -> Set[str]:
        with sqlite3.connect(self.history_db_path) as conn:
            rows = conn.execute("SELECT wazuh_alert_id FROM seen_alert_ids").fetchall()
        return {str(row[0]) for row in rows}

    def count_seen_alert_ids(self) -> int:
        with sqlite3.connect(self.history_db_path) as conn:
            row = conn.execute("SELECT COUNT(*) FROM seen_alert_ids").fetchone()
        return int(row[0]) if row else 0

    def has_seen_alert_id(self, alert_id: str) -> bool:
        with sqlite3.connect(self.history_db_path) as conn:
            row = conn.execute(
                "SELECT 1 FROM seen_alert_ids WHERE wazuh_alert_id = ? LIMIT 1", (alert_id,)
            ).fetchone()
        return row is not None

    def quarantine_add(
        self,
        wazuh_alert_id: str,
        source_index: str = "",
        source_document_id: str = "",
        error_type: str = "",
    ) -> int:
        """Catat alert yang rusak secara deterministik ke quarantine durable (upsert).

        Pelanggaran berulang pada ID yang sama menaikkan ``count``/``last_seen`` sementara
        ``first_seen`` dipertahankan, sehingga tabel quarantine tetap terlihat di status
        tanpa bertambah setiap retry.

        Mengembalikan ``count`` per ID setelah pelanggaran ini (1 pada pelanggaran pertama),
        agar pemanggil bisa mencatat quarantine pertama sebagai error dan pengulangannya sebagai debug.
        """
        counts = self.quarantine_add_many([{
            "wazuh_alert_id": wazuh_alert_id,
            "source_index": source_index,
            "source_document_id": source_document_id,
            "error_type": error_type,
        }])
        return counts[0]

    def quarantine_add_many(self, entries: List[Dict[str, Any]]) -> List[int]:
        """Catat sekumpulan entri quarantine dalam satu transaksi.

        Satu koneksi / satu commit untuk seluruh batch (ditambah satu kali baca balik
        untuk jumlah akhirnya). Mengembalikan ``count`` per ID setelah flush ini, sesuai urutan entri.
        """
        if not entries:
            return []
        now = datetime.now(timezone.utc).isoformat()
        rows = [
            (
                str(e.get("wazuh_alert_id", "")),
                str(e.get("source_index", "") or ""),
                str(e.get("source_document_id", "") or ""),
                str(e.get("error_type", "") or ""),
                now,
                now,
            )
            for e in entries
        ]
        with sqlite3.connect(self.history_db_path) as conn:
            conn.executemany(
                """
                INSERT INTO quarantined_alerts
                    (wazuh_alert_id, source_index, source_document_id, error_type, count, first_seen, last_seen)
                VALUES (?, ?, ?, ?, 1, ?, ?)
                ON CONFLICT(wazuh_alert_id) DO UPDATE SET
                    source_index = excluded.source_index,
                    source_document_id = excluded.source_document_id,
                    error_type = excluded.error_type,
                    count = quarantined_alerts.count + 1,
                    last_seen = excluded.last_seen
                """,
                rows,
            )
            conn.commit()
            counts = []
            for (alert_id, *_rest) in rows:
                row = conn.execute(
                    "SELECT count FROM quarantined_alerts WHERE wazuh_alert_id = ?",
                    (alert_id,),
                ).fetchone()
                counts.append(int(row[0]) if row else 0)
        return counts

    def quarantine_release(self, wazuh_alert_id: str) -> int:
        """Hapus satu ID yang dikarantina; kembalikan jumlah baris terdampak (1 dilepas, 0 tidak ada)."""
        with sqlite3.connect(self.history_db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM quarantined_alerts WHERE wazuh_alert_id = ?",
                (str(wazuh_alert_id),),
            )
            conn.commit()
            return int(cursor.rowcount or 0)

    def quarantine_count(self) -> int:
        """Kembalikan COUNT(*) alert yang dikarantina (status memakai ini, bukan len(list))."""
        with sqlite3.connect(self.history_db_path) as conn:
            row = conn.execute("SELECT COUNT(*) FROM quarantined_alerts").fetchone()
        return int(row[0]) if row else 0

    def excluded_add_many(self, alerts: List[CanonicalRawAlert]) -> None:
        """Catat alert agen yang dikecualikan (idempoten per wazuh_alert_id)."""
        if not alerts:
            return
        with sqlite3.connect(self.history_db_path) as conn:
            conn.executemany(
                "INSERT OR IGNORE INTO excluded_alerts (wazuh_alert_id, agent, event_time) VALUES (?, ?, ?)",
                (
                    (
                        a.wazuh_alert_id,
                        str(a.agent_name if a.agent_name and a.agent_name != "unknown" else a.agent_id).lower(),
                        a.timestamp.isoformat(),
                    )
                    for a in alerts
                ),
            )
            conn.commit()

    def excluded_counts(self) -> Dict[str, int]:
        """Counter kumulatif alert unik yang dikecualikan, per agen."""
        with sqlite3.connect(self.history_db_path) as conn:
            rows = conn.execute("SELECT agent, COUNT(*) FROM excluded_alerts GROUP BY agent ORDER BY agent").fetchall()
        return {str(agent): int(count) for agent, count in rows}

    def verdict_set(self, meta_id: int, verdict: str, note: str = "", labeled_by: str = "") -> Dict[str, Any]:
        """Simpan (atau ganti) label analyst untuk satu MetaAlert final."""
        labeled_at = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.history_db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO analyst_verdict (meta_id, verdict, note, labeled_by, labeled_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (int(meta_id), str(verdict), str(note or ""), str(labeled_by or ""), labeled_at),
            )
            conn.commit()
        return {"meta_id": int(meta_id), "verdict": verdict, "note": note or "", "labeled_by": labeled_by or "",
                "labeled_at": labeled_at}

    def verdict_map(self) -> Dict[int, Dict[str, Any]]:
        """Semua label analyst, meta_id -> {meta_id, verdict, note, labeled_by, labeled_at}."""
        with sqlite3.connect(self.history_db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT meta_id, verdict, note, labeled_by, labeled_at FROM analyst_verdict").fetchall()
        return {int(r["meta_id"]): dict(r) for r in rows}

    def suppression_add(self, meta_id: int, reason: str) -> None:
        """Tahan notifikasi untuk satu meta ID final (idempoten, alasan pertama yang dipakai).

        Dipanggil oleh dispatcher lewat getattr; tidak pernah error bila ditahan ulang.
        """
        with sqlite3.connect(self.history_db_path) as conn:
            conn.execute(
                "INSERT OR IGNORE INTO suppressed_notifications (meta_id, reason) VALUES (?, ?)",
                (int(meta_id), str(reason or "")),
            )
            conn.commit()

    def suppression_count(self) -> int:
        """Kembalikan COUNT(*) meta ID yang notifikasinya ditahan."""
        with sqlite3.connect(self.history_db_path) as conn:
            row = conn.execute("SELECT COUNT(*) FROM suppressed_notifications").fetchone()
        return int(row[0]) if row else 0

    def notification_add(self, meta_id: int, run_id: str, verdict: str) -> int:
        """Tambahkan satu putusan notifikasi dispatcher ke notification_log.

        Dipanggil oleh dispatcher lewat getattr; mengembalikan row id AUTOINCREMENT dari
        baris putusan yang ditambahkan.
        """
        # Dispatcher mencatat SENT tepat setelah sendMessage sukses: itulah sent_at (latensi T7).
        sent_at = datetime.now(timezone.utc).isoformat() if verdict == "SENT" else None
        with sqlite3.connect(self.history_db_path) as conn:
            cursor = conn.execute(
                "INSERT INTO notification_log (meta_id, run_id, verdict, sent_at) VALUES (?, ?, ?, ?)",
                (int(meta_id), str(run_id), str(verdict), sent_at),
            )
            conn.commit()
            return int(cursor.lastrowid or 0)

    def latency_samples(self, start_iso: str, end_iso: str) -> Dict[str, List[float]]:
        """Sampel latensi (detik) untuk MetaAlert yang difinalkan pada [start_iso, end_iso).

        * ``event_to_finalize``: finalized_at - end_time MetaAlert (event terakhir anggota).
        * ``finalize_to_sent``: sent_at Telegram pertama yang sukses - finalized_at.
        Baris sebelum migrasi T7 (finalized_at NULL) tidak ikut dihitung.
        """
        with sqlite3.connect(self.history_db_path) as conn:
            rows = conn.execute(
                """
                SELECT h.finalized_at, json_extract(h.scored_data, '$.end_time'),
                       (SELECT MIN(n.sent_at) FROM notification_log n
                        WHERE n.meta_id = h.meta_id AND n.verdict = 'SENT' AND n.sent_at IS NOT NULL)
                FROM finalized_history h
                WHERE h.finalized_at IS NOT NULL AND h.finalized_at >= ? AND h.finalized_at < ?
                """,
                (start_iso, end_iso),
            ).fetchall()
        out: Dict[str, List[float]] = {"event_to_finalize": [], "finalize_to_sent": []}
        for finalized_at, end_time, sent_at in rows:
            fin = datetime.fromisoformat(finalized_at)
            if end_time:
                out["event_to_finalize"].append((fin - datetime.fromisoformat(end_time)).total_seconds())
            if sent_at:
                out["finalize_to_sent"].append((datetime.fromisoformat(sent_at) - fin).total_seconds())
        return out

    def latency_summary(self, start_iso: str, end_iso: str) -> Dict[str, Optional[float]]:
        """p50/p95 (detik) dari :meth:`latency_samples`; None bila tidak ada sampel."""
        import numpy as np

        summary: Dict[str, Optional[float]] = {}
        for name, values in self.latency_samples(start_iso, end_iso).items():
            summary[f"{name}_n"] = len(values)
            for q in (50, 95):
                summary[f"{name}_p{q}"] = float(np.percentile(values, q)) if values else None
        return summary

    def notification_count(self) -> int:
        """Kembalikan COUNT(*) putusan notifikasi dispatcher yang tercatat."""
        with sqlite3.connect(self.history_db_path) as conn:
            row = conn.execute("SELECT COUNT(*) FROM notification_log").fetchone()
        return int(row[0]) if row else 0

    def notification_verdicts(self, limit: int = 100) -> List[str]:
        """Kembalikan putusan notifikasi terbaru, yang terbaru lebih dulu (bukti shadow-run)."""
        with sqlite3.connect(self.history_db_path) as conn:
            rows = conn.execute(
                "SELECT verdict FROM notification_log ORDER BY id DESC LIMIT ?",
                (max(1, int(limit)),),
            ).fetchall()
        return [str(row[0]) for row in rows]

    def quarantine_id_set(self) -> Set[str]:
        """Kembalikan ID yang dikarantina saja sebagai set (filter skip yang murah per siklus).

        SELECT satu kolom, berbeda dengan :meth:`quarantine_list` yang mengambil kolom
        tampilan urut terbaru untuk ditampilkan ke operator.
        """
        with sqlite3.connect(self.history_db_path) as conn:
            rows = conn.execute("SELECT wazuh_alert_id FROM quarantined_alerts").fetchall()
        return {str(row[0]) for row in rows}

    def quarantine_list(self) -> List[Dict[str, Any]]:
        """Kembalikan alert yang dikarantina, terbaru lebih dulu, untuk ditampilkan ke operator."""
        with sqlite3.connect(self.history_db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT wazuh_alert_id, source_index, source_document_id, error_type,"
                " count, first_seen, last_seen FROM quarantined_alerts"
                " ORDER BY last_seen DESC, wazuh_alert_id ASC"
            ).fetchall()
        return [dict(row) for row in rows]

    def get_derivation_hash(self) -> Optional[str]:
        """Kembalikan hash derivasi canonicalizer yang tersimpan, atau None bila belum ada."""
        with sqlite3.connect(self.history_db_path) as conn:
            row = conn.execute("SELECT derivation_hash FROM derivation_state WHERE id = 1").fetchone()
        return str(row[0]) if row else None

    def set_derivation_hash(self, derivation_hash: str) -> None:
        """Simpan hash derivasi canonicalizer untuk dibandingkan worker saat cek drift."""
        with sqlite3.connect(self.history_db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO derivation_state (id, derivation_hash) VALUES (1, ?)",
                (str(derivation_hash),),
            )
            conn.commit()

    @property
    def state_path(self) -> Path:
        """Kembalikan path file state yang sudah di-resolve."""
        return self.filepath

    def _backup_legacy_mirror_once(self) -> None:
        """Salin mirror JSON non-1.2 ke .pre-1.2.bak tepat satu kali sebelum ditimpa."""
        mirror_backup = self.filepath.with_name(self.filepath.name + ".pre-1.2.bak")
        try:
            if not self.filepath.exists() or mirror_backup.exists():
                return
            raw = self.filepath.read_text(encoding="utf-8")
            try:
                schema = json.loads(raw).get("schema_version") if raw.strip() else None
            except ValueError:
                schema = None
            if schema != "1.2":
                mirror_backup.write_text(raw, encoding="utf-8")
        except OSError:
            logger.warning("Legacy JSON mirror could not be backed up; proceeding with save")

    def save_state(
        self,
        engine: RBTAEngine,
        outbox: Optional[List[Dict[str, Any]]] = None,
        source_checkpoint: Optional[Dict[str, Any]] = None,
        new_finalized_history: Optional[List[Dict[str, Any]]] = None,
        pending_scoring: Optional[List[Dict[str, Any]]] = None,
        finalized_at: Optional[Dict[int, str]] = None,
    ) -> None:
        """Simpan state engine, bucket aktif, ID alert seen, pending scoring, dan outbox ke disk secara atomik."""
        self.filepath.parent.mkdir(parents=True, exist_ok=True)
        
        tmp_file = self.filepath.with_suffix(".tmp")

        # ID seen disimpan append-only di SQLite sehingga biaya checkpoint sebanding dengan
        # event baru, bukan menulis ulang seluruh riwayat replay sebagai JSON.
        new_seen_ids = set(getattr(engine, "_new_seen_alert_ids", set()))

        # Gagal tertutup bila meta_id bertabrakan, sebelum ada penulisan pada checkpoint ini.
        self._assert_no_finalized_collision(list(new_finalized_history or []))

        # Serialisasi meta counter.
        meta_id_counter = engine._meta_id_counter

        # Serialisasi state temporal agent.
        temporal_states_data: Dict[str, Dict[str, Any]] = {}
        for agent_id, state in engine._temporal_states.items():
            temporal_states_data[agent_id] = {
                "agent_id": state.agent_id,
                "agent_name": state.agent_name,
                "base_delta_t_sec": state.base_delta_t.total_seconds(),
                "adaptive": state.adaptive,
                "last_timestamp": state.last_timestamp.isoformat() if state.last_timestamp else None,
                "warmup_event_count": state.warmup_event_count,
                "warmup_gaps": list(state.warmup_gaps),
                "baseline_gap": state.baseline_gap,
                "ema_gap": state.ema_gap,
                "current_delta_t_sec": state.current_delta_t.total_seconds(),
                "is_warmed_up": state.is_warmed_up,
                "_is_terminal_invalid": state._is_terminal_invalid,
                "_invalid_reason": state._invalid_reason,
            }

        # Serialisasi bucket aktif.
        active_buckets_data: List[Dict[str, Any]] = []
        for (agent_id, rule_group), bucket in engine._active_buckets.items():
            active_buckets_data.append({
                "agent_id": agent_id,
                "rule_group_primary": rule_group,
                "meta_id": bucket.meta_id,
                "agent_name": bucket.agent_name,
                "start_time": bucket.start_time.isoformat(),
                "end_time": bucket.end_time.isoformat(),
                "alert_count": bucket.alert_count,
                "max_severity": bucket.max_severity,
                "rule_id_distribution": dict(bucket.rule_id_distribution),
                "severity_distribution": {str(k): v for k, v in bucket.severity_distribution.items()},
                "agent_criticality": bucket.agent_criticality,
                "wazuh_alert_ids": list(bucket.wazuh_alert_ids),
                "mitre_tactics_order": list(bucket.mitre_tactics_order),
                "critical_mitre_present": bucket.critical_mitre_present,
            })

        payload = {
            "schema_version": "1.2",
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "meta_id_counter": meta_id_counter,
            "temporal_states": temporal_states_data,
            "active_buckets": active_buckets_data,
            "source_checkpoint": source_checkpoint or {},
            "pending_scoring": pending_scoring or [],
            "outbox": outbox or [],
        }

        # Serialisasi dulu sebelum menulis apa pun. Satu commit SQLite menjadi acuan untuk
        # proteksi duplikat sekaligus mutasi RBTA yang dilindunginya.
        serialized = json.dumps(payload, indent=2)
        finalized_at = finalized_at or {}
        history_rows = [
            (item["meta_id"], json.dumps(item), finalized_at.get(int(item["meta_id"])))
            for item in (new_finalized_history or [])
        ]
        with sqlite3.connect(self.history_db_path) as conn:
            conn.execute("PRAGMA synchronous=FULL")
            conn.executemany(
                "INSERT OR IGNORE INTO finalized_history (meta_id, scored_data, finalized_at) VALUES (?, ?, ?)",
                history_rows,
            )
            conn.executemany(
                "INSERT OR IGNORE INTO seen_alert_ids (wazuh_alert_id) VALUES (?)",
                ((alert_id,) for alert_id in new_seen_ids),
            )
            conn.execute("INSERT OR REPLACE INTO runtime_snapshot (id, payload) VALUES (1, ?)", (serialized,))
        if hasattr(engine, "_new_seen_alert_ids"):
            engine._new_seen_alert_ids.difference_update(new_seen_ids)

        # Simpan mirror pra-1.2 tepat satu kali sebelum ditimpa.
        self._backup_legacy_mirror_once()

        # Hanya mirror untuk kompatibilitas/export; pemulihan selalu mengutamakan SQLite.
        try:
            tmp_file.write_text(serialized, encoding="utf-8")
            tmp_file.replace(self.filepath)
        except OSError:
            logger.warning("Runtime JSON mirror could not be published; committed SQLite snapshot remains authoritative")

    def restore_state(self, engine: RBTAEngine, hydrate_seen_ids: bool = True) -> Dict[str, Any]:
        """Pulihkan struktur internal engine dari disk ke instance RBTAEngine yang diberikan.

        Parameters
        ----------
        engine : RBTAEngine
            Instance engine tujuan yang akan diisi.

        Returns
        -------
        Dict[str, Any]
            Dict metadata hasil pemulihan berisi 'outbox' dan 'source_checkpoint'.
        """
        # Direktori state bisa saja terhapus di antara init manager dan restore (mis. dibersihkan
        # operator). Buat ulang supaya restore hanya gagal karena korupsi sungguhan, bukan karena
        # direktorinya tidak ada.
        self.history_db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.history_db_path) as conn:
            row = conn.execute("SELECT payload FROM runtime_snapshot WHERE id = 1").fetchone()
            if row is None:
                # Gagal tertutup: snapshot hilang tetapi ID seen masih ada berarti restore parsial/rusak —
                # jangan pernah mengisi dedup ke engine kosong, karena itu diam-diam memecah proteksi duplikat
                # (engine tanpa bucket/state temporal tetapi punya ID seen). State yang hanya berisi history
                # tetap bisa dipulihkan: memuat finalized history tidak menyentuh struktur dedup.
                seen_count = conn.execute("SELECT COUNT(*) FROM seen_alert_ids").fetchone()[0]
                if int(seen_count or 0) > 0:
                    raise RuntimeError(
                        "Runtime SQLite snapshot is missing while seen_alert_ids"
                        " is non-empty; refusing to hydrate dedup state into an empty engine —"
                        " restore the complete runtime backup instead"
                    )
        if row:
            data = json.loads(row[0])
        elif self.filepath.exists():
            with self.filepath.open("r", encoding="utf-8") as f:
                data = json.load(f)
            if data.get("schema_version") == "1.2":
                raise ValueError("Runtime SQLite snapshot missing; restore the complete runtime backup, not its JSON mirror")
        else:
            engine._seen_alert_ids = self.load_seen_alert_ids() if hydrate_seen_ids else set()
            engine._new_seen_alert_ids = set()
            # Restore yang hanya berisi history melanjutkan aliran meta_id dari MAX+1 supaya
            # bucket berikutnya tidak bertabrakan dengan history yang sudah di-commit.
            with sqlite3.connect(self.history_db_path) as conn:
                max_row = conn.execute("SELECT MAX(meta_id) FROM finalized_history").fetchone()
            engine._meta_id_counter = int(max_row[0]) + 1 if max_row and max_row[0] is not None else 1
            return {"outbox": [], "source_checkpoint": {}, "finalized_history": self.load_finalized_history()}

        # Pulihkan ID seen dan counter.
        legacy_seen_ids = set(data.get("seen_alert_ids", []))
        if legacy_seen_ids:
            self.append_seen_alert_ids(legacy_seen_ids)
        engine._seen_alert_ids = self.load_seen_alert_ids() if hydrate_seen_ids else set()
        engine._new_seen_alert_ids = set()
        engine._meta_id_counter = int(data.get("meta_id_counter", 1))

        # Pulihkan state temporal.
        engine._temporal_states.clear()
        for agent_id, state_dict in data.get("temporal_states", {}).items():
            from datetime import timedelta
            state = AgentTemporalState(
                agent_id=agent_id,
                agent_name=state_dict.get("agent_name", "unknown"),
                base_delta_t=timedelta(seconds=state_dict["base_delta_t_sec"]),
                adaptive=state_dict["adaptive"],
            )
            state.last_timestamp = datetime.fromisoformat(state_dict["last_timestamp"]) if state_dict["last_timestamp"] else None
            state.warmup_event_count = state_dict["warmup_event_count"]
            state.warmup_gaps = list(state_dict["warmup_gaps"])
            state.baseline_gap = state_dict["baseline_gap"]
            state.ema_gap = state_dict["ema_gap"]
            state.current_delta_t = timedelta(seconds=state_dict["current_delta_t_sec"])
            state.is_warmed_up = state_dict["is_warmed_up"]
            state._is_terminal_invalid = state_dict.get("_is_terminal_invalid", False)
            state._invalid_reason = state_dict.get("_invalid_reason")
            engine._temporal_states[agent_id] = state

        # Pulihkan bucket aktif.
        engine._active_buckets.clear()
        for b_dict in data.get("active_buckets", []):
            bucket = _ActiveBucket.__new__(_ActiveBucket)
            bucket.meta_id = b_dict["meta_id"]
            bucket.agent_id = b_dict["agent_id"]
            bucket.agent_name = b_dict["agent_name"]
            bucket.rule_group_primary = b_dict["rule_group_primary"]
            bucket.start_time = datetime.fromisoformat(b_dict["start_time"])
            bucket.end_time = datetime.fromisoformat(b_dict["end_time"])
            bucket.alert_count = b_dict["alert_count"]
            bucket.max_severity = b_dict["max_severity"]
            bucket.rule_id_distribution = Counter(b_dict["rule_id_distribution"])
            bucket.severity_distribution = Counter({int(k): v for k, v in b_dict["severity_distribution"].items()})
            bucket.agent_criticality = b_dict["agent_criticality"]
            bucket.wazuh_alert_ids = list(b_dict["wazuh_alert_ids"])
            bucket.mitre_tactics_order = list(b_dict["mitre_tactics_order"])
            bucket._mitre_seen = {t.casefold() for t in bucket.mitre_tactics_order}
            bucket.critical_mitre_present = b_dict["critical_mitre_present"]

            key = (bucket.agent_id, bucket.rule_group_primary)
            engine._active_buckets[key] = bucket
            # Kompatibilitas untuk file state yang dibuat sebelum agent_name ikut disimpan
            # di metadata state temporal.
            state = engine._temporal_states.get(bucket.agent_id)
            if state and state.agent_name == "unknown" and bucket.agent_name:
                state.agent_name = bucket.agent_name

        legacy_history = data.get("finalized_history", [])
        if legacy_history:
            self.append_finalized(legacy_history)

        return {
            "source_checkpoint": data.get("source_checkpoint", {}),
            "pending_scoring": data.get("pending_scoring", []),
            "outbox": data.get("outbox", []),
            "finalized_history": self.load_finalized_history(),
        }
