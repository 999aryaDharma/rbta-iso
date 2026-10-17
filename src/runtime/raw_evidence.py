import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Dict, List, Optional, Tuple, Union

from src.contracts.raw_alert import CanonicalRawAlert
from src.runtime.json_safe import (
    compute_canonical_fingerprint,
    deterministic_json_dumps,
    redact_sensitive_data,
    to_json_safe,
)


class RawEvidenceConflictError(Exception):
    """Dilempar bila alert dengan wazuh_alert_id yang sama punya bukti kanonis yang bertentangan."""
    pass


class RawEvidenceIntegrityError(Exception):
    """Dilempar bila data raw evidence yang tersimpan melanggar integritas skema atau timestamp."""
    pass


class RawAlertEvidenceStore:
    """RawAlertEvidenceStore — persistensi raw alert evidence berbasis SQLite dengan mode WAL.

    Jaminan:
    - Buffer tulis per batch dengan journal WAL dan synchronous FULL.
    - Duplikat idempoten: fingerprint alert identik -> NO-OP (mengembalikan False).
    - Duplikat bertentangan: fingerprint berbeda -> melempar RawEvidenceConflictError (gagal tertutup).
    - Keanggotaan sumber MetaAlert bisa ditelusuri persis (source_total, resolved_total, unresolved_ids).
    - Pencarian multi-field: ID alert, rule ID, deskripsi, IP, full log.
    - Flush otomatis di setiap query baca agar konsistensi read-your-own-writes 100%.
    """

    def __init__(self, db_path: Optional[Union[str, Path]] = None, batch_size: int = 1000) -> None:
        if db_path is None:
            import os
            db_path = os.environ.get("RBTA_RAW_EVIDENCE_DB", "data/runtime/raw_alert_evidence.sqlite3")

        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.batch_size = batch_size
        self._lock = threading.Lock()
        self._write_buffer: List[Tuple] = []
        self._recent_fingerprints: Dict[str, str] = {}
        self._max_recent_fingerprints = 100000
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            conn = sqlite3.connect(str(self.db_path), timeout=30.0, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA cache_size=-64000")
            conn.execute("PRAGMA temp_store=MEMORY")
            conn.execute("PRAGMA busy_timeout=30000")
            self._conn = conn
        return self._conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._get_conn()
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS raw_alert_evidence (
                    wazuh_alert_id TEXT PRIMARY KEY,
                    canonical_fingerprint TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    agent_name TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    rule_level INTEGER NOT NULL,
                    rule_description TEXT DEFAULT '',
                    rule_group_primary TEXT NOT NULL,
                    rule_groups_all TEXT DEFAULT '[]',
                    mitre_tactics TEXT DEFAULT '[]',
                    mitre_techniques TEXT DEFAULT '[]',
                    srcip TEXT,
                    location TEXT DEFAULT '',
                    decoder TEXT DEFAULT '',
                    full_log TEXT DEFAULT '',
                    agent_criticality REAL NOT NULL,
                    metadata TEXT DEFAULT '{}',
                    original_source_payload TEXT,
                    source_index TEXT DEFAULT '',
                    source_document_id TEXT DEFAULT '',
                    source_mode TEXT DEFAULT 'LIVE',
                    ingested_at TEXT NOT NULL
                )
                """
            )
            # Migrasi skema otomatis untuk database sqlite yang sudah ada.
            cursor = conn.execute("PRAGMA table_info(raw_alert_evidence)")
            existing_cols = {row["name"] for row in cursor.fetchall()}

            column_defs = {
                "canonical_fingerprint": "TEXT NOT NULL DEFAULT ''",
                "fingerprint_version": "INTEGER NOT NULL DEFAULT 1",
                "rule_description": "TEXT DEFAULT ''",
                "rule_groups_all": "TEXT DEFAULT '[]'",
                "mitre_tactics": "TEXT DEFAULT '[]'",
                "mitre_techniques": "TEXT DEFAULT '[]'",
                "srcip": "TEXT",
                "location": "TEXT DEFAULT ''",
                "decoder": "TEXT DEFAULT ''",
                "full_log": "TEXT DEFAULT ''",
                "metadata": "TEXT DEFAULT '{}'",
                "original_source_payload": "TEXT",
                "source_index": "TEXT DEFAULT ''",
                "source_document_id": "TEXT DEFAULT ''",
                "source_mode": "TEXT DEFAULT 'LIVE'",
                "ingested_at": "TEXT NOT NULL DEFAULT ''",
            }
            for col_name, col_def in column_defs.items():
                if col_name not in existing_cols:
                    conn.execute(f"ALTER TABLE raw_alert_evidence ADD COLUMN {col_name} {col_def}")

            conn.execute("CREATE INDEX IF NOT EXISTS idx_raw_agent ON raw_alert_evidence (agent_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_raw_rule ON raw_alert_evidence (rule_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_raw_timestamp ON raw_alert_evidence (timestamp)")
            conn.commit()

            row = conn.execute("SELECT COUNT(*) AS total FROM raw_alert_evidence").fetchone()
            self._cached_count = int(row["total"]) if row else 0

    def flush(self) -> None:
        """Commit record raw evidence yang masih di buffer ke disk saat itu juga."""
        with self._lock:
            self._flush_locked()

    def _flush_locked(self) -> None:
        """Flush buffer tulis; pemanggil wajib memegang ``self._lock``."""
        if not self._write_buffer:
            return
        conn = self._get_conn()
        conn.executemany(
            """
            INSERT OR IGNORE INTO raw_alert_evidence (
                wazuh_alert_id, canonical_fingerprint, fingerprint_version, timestamp, agent_id, agent_name,
                rule_id, rule_level, rule_description, rule_group_primary, rule_groups_all,
                mitre_tactics, mitre_techniques, srcip, location, decoder,
                full_log, agent_criticality, metadata, original_source_payload,
                source_index, source_document_id, source_mode, ingested_at
            ) VALUES (
                ?, ?, 2, ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?
            )
            """,
            self._write_buffer,
        )
        conn.commit()
        self._write_buffer.clear()

    def store(
        self,
        alert: CanonicalRawAlert,
        original_payload: Optional[Dict[str, Any]] = None,
        source_mode: str = "LIVE",
        skip_conflict_check: bool = False,
    ) -> bool:
        """Simpan raw alert kanonis dengan buffer tulis ber-throughput tinggi.

        Returns
        -------
        bool
            True bila baru dimasukkan, False bila duplikat identik.

        Raises
        ------
        RawEvidenceConflictError
            Bila wazuh_alert_id sudah ada dengan atribut kanonis yang bertentangan.
            Flag lama ``skip_conflict_check`` dipertahankan untuk kompatibilitas API tetapi
            tidak pernah melemahkan pengecekan ini: ingestion replay juga menjalankan deteksi
            konflik kanonis penuh.
        """
        meta = alert.metadata if isinstance(alert.metadata, dict) else dict(alert.metadata)

        # Ambil field audit/tambahan dengan aman.
        rule_desc = meta.get("rule_description", getattr(alert, "rule_description", ""))
        rule_groups_all = meta.get("rule_groups_all", [alert.rule_group_primary])
        mitre_techs = meta.get("mitre_techniques", ())
        loc = meta.get("location", "")
        dec = meta.get("decoder", "")
        if dec is None:
            dec = ""
        elif not isinstance(dec, str):
            dec = deterministic_json_dumps(dec)
        flog = meta.get("full_log", "")

        # Satukan index sumber / doc id.
        source_index = meta.get("source_index", meta.get("opensearch_index", ""))
        source_doc_id = meta.get("source_document_id", meta.get("opensearch_document_id", ""))

        # Dulu replay hanya meng-hash ID/timestamp/agent dan melewati cek duplikat. Optimasi itu
        # membuat jumlah evidence tidak akurat dan bisa menyembunyikan payload rule/severity yang
        # bertentangan di balik ID Wazuh yang sama. Flag lama dipertahankan untuk kompatibilitas
        # API, tetapi integritas evidence tidak pernah dilemahkan.
        fingerprint = compute_canonical_fingerprint(
            wazuh_alert_id=alert.wazuh_alert_id,
            timestamp=alert.timestamp,
            agent_id=alert.agent_id,
            agent_name=alert.agent_name,
            rule_id=alert.rule_id,
            rule_level=alert.rule_level,
            rule_group_primary=alert.rule_group_primary,
            srcip=alert.srcip or "",
            agent_criticality=alert.agent_criticality,
            mitre_tactics=alert.mitre_tactics,
            metadata=meta,
        )

        with self._lock:
            if alert.wazuh_alert_id in self._recent_fingerprints:
                existing_fp = self._recent_fingerprints[alert.wazuh_alert_id]
                if existing_fp == fingerprint:
                    return False
                raise RawEvidenceConflictError(
                    f"Conflicting canonical evidence detected for wazuh_alert_id='{alert.wazuh_alert_id}'. "
                    f"Existing fingerprint '{existing_fp}' != incoming '{fingerprint}'."
                )

            conn = self._get_conn()
            row = conn.execute(
                "SELECT * FROM raw_alert_evidence WHERE wazuh_alert_id = ?",
                (alert.wazuh_alert_id,),
            ).fetchone()

            if row is not None:
                existing_fp = row["canonical_fingerprint"]
                if not existing_fp:
                    raise RawEvidenceIntegrityError(
                        f"Stored raw evidence for wazuh_alert_id='{alert.wazuh_alert_id}' has an empty"
                        f" canonical fingerprint (fingerprint_version={row['fingerprint_version']});"
                        " the evidence row is corrupt and must be repaired, not overwritten"
                    )
                if row["fingerprint_version"] == 1:
                    fields = {name: row[name] for name in (
                        "wazuh_alert_id", "timestamp", "agent_id", "agent_name", "rule_id", "rule_level",
                        "rule_group_primary", "srcip", "agent_criticality",
                    )}
                    fields["metadata"] = json.loads(row["metadata"])
                    fields["mitre_tactics"] = json.loads(row["mitre_tactics"])
                    if compute_canonical_fingerprint(**fields, version=1) != existing_fp:
                        raise RawEvidenceIntegrityError("Legacy evidence fingerprint does not match stored canonical content")
                    # Bandingkan isi yang sudah dinormalisasi tanpa menulis ulang hash historis.
                    existing_fp = compute_canonical_fingerprint(**fields)
                elif row["fingerprint_version"] != 2:
                    raise RawEvidenceIntegrityError("Unsupported stored fingerprint version")
                if len(self._recent_fingerprints) < self._max_recent_fingerprints:
                    self._recent_fingerprints[alert.wazuh_alert_id] = existing_fp
                if existing_fp == fingerprint:
                    return False
                raise RawEvidenceConflictError(
                    f"Conflicting canonical evidence detected for wazuh_alert_id='{alert.wazuh_alert_id}'. "
                    f"Existing fingerprint '{existing_fp}' != incoming '{fingerprint}'."
                )

            if len(self._recent_fingerprints) >= self._max_recent_fingerprints:
                # Baris yang masih di buffer dan belum di-flush tidak terlihat oleh SELECT di atas, jadi
                # cache harus di-commit ke SQLite dulu sebelum dikosongkan — kalau tidak, konflik dengan
                # baris yang masih di buffer tidak terdeteksi.
                self._flush_locked()
                self._recent_fingerprints.clear()
            self._recent_fingerprints[alert.wazuh_alert_id] = fingerprint

            ingested_at = datetime.now(timezone.utc).isoformat()
            ts_str = alert.timestamp.isoformat() if isinstance(alert.timestamp, datetime) else str(alert.timestamp)
            
            original_payload_str = deterministic_json_dumps(original_payload) if original_payload is not None else None
            meta_str = deterministic_json_dumps(meta)

            record = (
                alert.wazuh_alert_id,
                fingerprint,
                ts_str,
                alert.agent_id,
                alert.agent_name,
                alert.rule_id,
                alert.rule_level,
                rule_desc,
                alert.rule_group_primary,
                json.dumps(to_json_safe(rule_groups_all)),
                json.dumps(to_json_safe(alert.mitre_tactics)),
                json.dumps(to_json_safe(mitre_techs)),
                alert.srcip or "",
                loc,
                dec,
                flog,
                float(alert.agent_criticality),
                meta_str,
                original_payload_str,
                source_index,
                source_doc_id,
                source_mode,
                ingested_at,
            )
            self._write_buffer.append(record)
            self._cached_count = getattr(self, "_cached_count", 0) + 1

            if len(self._write_buffer) >= self.batch_size:
                conn.executemany(
                    """
                    INSERT OR IGNORE INTO raw_alert_evidence (
                        wazuh_alert_id, canonical_fingerprint, fingerprint_version, timestamp, agent_id, agent_name,
                        rule_id, rule_level, rule_description, rule_group_primary, rule_groups_all,
                        mitre_tactics, mitre_techniques, srcip, location, decoder,
                        full_log, agent_criticality, metadata, original_source_payload,
                        source_index, source_document_id, source_mode, ingested_at
                    ) VALUES (
                        ?, ?, 2, ?, ?, ?,
                        ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?,
                        ?, ?, ?, ?,
                        ?, ?, ?, ?
                    )
                    """,
                    self._write_buffer,
                )
                conn.commit()
                self._write_buffer.clear()
            return True

    def _row_to_dict(self, row: sqlite3.Row, redact: bool = False) -> Dict[str, Any]:
        d = dict(row)
        d["rule_groups_all"] = json.loads(d.get("rule_groups_all") or "[]")
        d["mitre_tactics"] = json.loads(d.get("mitre_tactics") or "[]")
        d["mitre_techniques"] = json.loads(d.get("mitre_techniques") or "[]")
        try:
            d["metadata"] = json.loads(d.get("metadata") or "{}")
        except Exception:
            d["metadata"] = {}

        if d.get("original_source_payload"):
            try:
                d["original_source_payload"] = json.loads(d["original_source_payload"])
            except Exception:
                pass

        if redact:
            d = redact_sensitive_data(d)
        return d

    def get(self, wazuh_alert_id: str, redact: bool = False) -> Optional[Dict[str, Any]]:
        """Ambil satu record raw alert evidence berdasarkan ID."""
        self.flush()
        with self._lock:
            conn = self._get_conn()
            row = conn.execute(
                "SELECT * FROM raw_alert_evidence WHERE wazuh_alert_id = ?",
                (wazuh_alert_id,),
            ).fetchone()
            if not row:
                return None
            return self._row_to_dict(row, redact=redact)

    def get_many(self, wazuh_alert_ids: List[str], redact: bool = False) -> Dict[str, Dict[str, Any]]:
        """Ambil beberapa record raw alert evidence, dipetakan per ID."""
        if not wazuh_alert_ids:
            return {}

        self.flush()
        results: Dict[str, Dict[str, Any]] = {}
        with self._lock:
            conn = self._get_conn()
            # Query per 500 untuk menghormati batas parameter SQLite.
            chunk_size = 500
            for i in range(0, len(wazuh_alert_ids), chunk_size):
                chunk = wazuh_alert_ids[i:i + chunk_size]
                placeholders = ",".join("?" for _ in chunk)
                rows = conn.execute(
                    f"SELECT * FROM raw_alert_evidence WHERE wazuh_alert_id IN ({placeholders})",
                    chunk,
                ).fetchall()
                for row in rows:
                    rec = self._row_to_dict(row, redact=redact)
                    results[rec["wazuh_alert_id"]] = rec
        return results

    def resolve_provenance_members(self, source_alert_ids: List[str]) -> Dict[str, Any]:
        """Resolusi setiap anggota sumber dengan urutan kanonis untuk penelusuran MetaAlert.

        Evidence yang hilang sengaja ditampilkan sebagai anggota yang belum ter-resolve agar API
        tidak pernah menampilkan jejak parsial seolah lengkap. Field yang dipilih adalah proyeksi
        audit yang aman; payload mentah dan kredensial tidak pernah dikembalikan dari method ini.
        """
        resolved_map = self.get_many(source_alert_ids, redact=True)
        members: List[Dict[str, Any]] = []
        unresolved: List[str] = []
        fields = (
            "timestamp", "agent_id", "agent_name", "rule_id", "rule_description",
            "rule_group_primary", "source_index", "source_document_id", "source_mode",
            "canonical_fingerprint",
        )
        for alert_id in source_alert_ids:
            evidence = resolved_map.get(alert_id)
            if evidence is None:
                unresolved.append(alert_id)
                members.append({"wazuh_alert_id": alert_id, "resolved": False, **{field: None for field in fields}})
                continue
            members.append({
                "wazuh_alert_id": alert_id,
                "resolved": True,
                **{field: evidence.get(field) for field in fields},
            })
        return {
            "source_total": len(source_alert_ids),
            "resolved_total": len(resolved_map),
            "unresolved_alert_ids": unresolved,
            "members": members,
        }

    def get_meta_alert_raw_alerts(
        self,
        source_alert_ids: List[str],
        meta_id: Optional[int] = None,
        page: int = 1,
        page_size: int = 50,
        search: Optional[str] = None,
        rule_id: Optional[str] = None,
        level_min: Optional[int] = None,
        level_max: Optional[int] = None,
        srcip: Optional[str] = None,
        mitre_tactic: Optional[str] = None,
        redact: bool = True,
    ) -> Dict[str, Any]:
        """Resolusi raw alert anggota sebuah MetaAlert dengan penelusuran resolusi yang ketat dan filter."""
        source_total = len(source_alert_ids)
        resolved_map = self.get_many(source_alert_ids, redact=redact)
        resolved_total = len(resolved_map)

        # Kenali ID alert yang belum ter-resolve sambil menjaga urutan sumber kanonis.
        unresolved_alert_ids = [aid for aid in source_alert_ids if aid not in resolved_map]

        # Kumpulkan record yang ter-resolve dengan urutan sumber kanonis.
        resolved_items = [resolved_map[aid] for aid in source_alert_ids if aid in resolved_map]

        # Terapkan pencarian multi-field dan filter.
        filtered_items = []
        search_lower = search.strip().lower() if search else None

        for item in resolved_items:
            if rule_id and item.get("rule_id") != rule_id:
                continue
            if level_min is not None and item.get("rule_level", 0) < level_min:
                continue
            if level_max is not None and item.get("rule_level", 0) > level_max:
                continue
            if srcip and item.get("srcip") != srcip:
                continue
            if mitre_tactic and mitre_tactic not in item.get("mitre_tactics", []):
                continue
            if search_lower:
                match = (
                    search_lower in item.get("wazuh_alert_id", "").lower()
                    or search_lower in item.get("rule_id", "").lower()
                    or search_lower in item.get("rule_description", "").lower()
                    or search_lower in item.get("full_log", "").lower()
                    or search_lower in item.get("srcip", "").lower()
                )
                if not match:
                    continue
            filtered_items.append(item)

        filtered_total = len(filtered_items)
        start_idx = max(0, (page - 1) * page_size)
        end_idx = start_idx + page_size
        paginated_items = filtered_items[start_idx:end_idx]

        return {
            "meta_id": meta_id,
            "source_total": source_total,
            "resolved_total": resolved_total,
            "filtered_total": filtered_total,
            "unresolved_alert_ids": unresolved_alert_ids,
            "page": page,
            "page_size": page_size,
            "items": paginated_items,
        }

    def search(
        self,
        query: Optional[str] = None,
        rule_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        srcip: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
        redact: bool = True,
    ) -> List[Dict[str, Any]]:
        """Cari raw alert evidence di beberapa index."""
        self.flush()
        conditions = []
        params: List[Any] = []

        if query:
            conditions.append(
                "(wazuh_alert_id LIKE ? OR rule_id LIKE ? OR rule_description LIKE ? OR full_log LIKE ? OR srcip LIKE ?)"
            )
            like = f"%{query}%"
            params.extend([like, like, like, like, like])
        if rule_id:
            conditions.append("rule_id = ?")
            params.append(rule_id)
        if agent_id:
            conditions.append("agent_id = ?")
            params.append(agent_id)
        if srcip:
            conditions.append("srcip = ?")
            params.append(srcip)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = f"SELECT * FROM raw_alert_evidence {where_clause} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._lock:
            conn = self._get_conn()
            rows = conn.execute(sql, params).fetchall()
            return [self._row_to_dict(r, redact=redact) for r in rows]

    def count(self) -> int:
        """Kembalikan jumlah record raw alert evidence yang tersimpan, langsung dari cache memori."""
        if hasattr(self, "_cached_count"):
            return self._cached_count
        self.flush()
        with self._lock:
            conn = self._get_conn()
            row = conn.execute("SELECT COUNT(*) AS total FROM raw_alert_evidence").fetchone()
            self._cached_count = int(row["total"]) if row else 0
            return self._cached_count

    def latest_agent_names(self) -> Dict[str, str]:
        """Kembalikan nama kanonis terbaru (bukan placeholder) untuk setiap agent.

        Proyeksi sempit ini mendukung telemetri replay lama tanpa membuka payload raw alert.
        Sengaja read-only dan tidak memengaruhi evidence kanonis maupun agregasi RBTA.
        """
        self.flush()
        with self._lock:
            rows = self._get_conn().execute(
                """
                SELECT agent_id, agent_name FROM (
                    SELECT agent_id, agent_name,
                           ROW_NUMBER() OVER (
                               PARTITION BY agent_id
                               ORDER BY timestamp DESC, wazuh_alert_id DESC
                           ) AS row_number
                    FROM raw_alert_evidence
                    WHERE trim(agent_name) <> '' AND lower(agent_name) <> 'unknown'
                ) WHERE row_number = 1
                """
            ).fetchall()
        return {str(row["agent_id"]): str(row["agent_name"]) for row in rows}

    def export_canonical_alerts(self) -> List[CanonicalRawAlert]:
        """Export evidence run yang terisolasi sebagai alert kanonis berurutan menurut event-time."""
        self.flush()
        with self._lock:
            rows = self._get_conn().execute(
                "SELECT * FROM raw_alert_evidence ORDER BY timestamp ASC, wazuh_alert_id ASC"
            ).fetchall()

        alerts: List[CanonicalRawAlert] = []
        for row in rows:
            item = self._row_to_dict(row, redact=False)
            alerts.append(
                CanonicalRawAlert(
                    wazuh_alert_id=item["wazuh_alert_id"],
                    timestamp=datetime.fromisoformat(str(item["timestamp"]).replace("Z", "+00:00")),
                    agent_id=item["agent_id"],
                    agent_name=item["agent_name"],
                    rule_group_primary=item["rule_group_primary"],
                    rule_level=int(item["rule_level"]),
                    rule_id=item["rule_id"],
                    mitre_tactics=tuple(item.get("mitre_tactics") or ()),
                    srcip=item.get("srcip") or None,
                    agent_criticality=float(item["agent_criticality"]),
                    metadata=MappingProxyType(item.get("metadata") or {}),
                )
            )
        return alerts

    def count_by_hour(
        self,
        start_time: datetime,
        end_time: datetime,
    ) -> Dict[str, int]:
        """Agregasi jumlah raw alert ke bucket per jam UTC di dalam [start_time, end_time].

        Returns
        -------
        Dict[str, int]
            Peta 'YYYY-MM-DD HH:00' -> jumlah raw alert dengan timestamp di jam tersebut.
        """
        self.flush()
        st_utc = start_time.astimezone(timezone.utc) if start_time.tzinfo else start_time.replace(tzinfo=timezone.utc)
        et_utc = end_time.astimezone(timezone.utc) if end_time.tzinfo else end_time.replace(tzinfo=timezone.utc)
        start_iso = st_utc.isoformat()
        end_iso = et_utc.isoformat()

        sql = "SELECT wazuh_alert_id, timestamp FROM raw_alert_evidence WHERE timestamp >= ? AND timestamp <= ?"
        hourly_counts: Dict[str, int] = {}
        with self._lock:
            conn = self._get_conn()
            rows = conn.execute(sql, (start_iso, end_iso)).fetchall()
            for r in rows:
                ts_raw = r["timestamp"]
                try:
                    if isinstance(ts_raw, str):
                        dt = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).astimezone(timezone.utc)
                    else:
                        dt = ts_raw.astimezone(timezone.utc)
                    hour_key = dt.strftime("%Y-%m-%d %H:00")
                    hourly_counts[hour_key] = hourly_counts.get(hour_key, 0) + 1
                except Exception as exc:
                    raise RawEvidenceIntegrityError(
                        f"Corrupt timestamp '{ts_raw}' encountered in raw evidence record '{r['wazuh_alert_id']}': {exc}"
                    ) from exc
        return hourly_counts
