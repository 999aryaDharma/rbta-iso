"""Ekspor manual bukti harian live (T6) dari state durable, tanpa service yang berjalan.

Contoh di CT (di dalam container, state live):
    docker compose exec rbta-service python scripts/export_live_evidence.py --date 2026-10-16

Default tanggal = kemarin (WITA). Definisi kolom ada di src/runtime/evidence_export.py.
"""

import argparse
from datetime import date, datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.runtime.durable_state import DurableStateManager  # noqa: E402
from src.runtime.evidence_export import WITA, export_analyst_verdicts, export_day, load_source_state  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Ekspor CSV bukti harian live")
    parser.add_argument("--state-file", default=os.environ.get("RBTA_STATE_FILE", "data/runtime/state.json"))
    parser.add_argument(
        "--evidence-db", default=os.environ.get("RBTA_RAW_EVIDENCE_DB", "data/runtime/raw_alert_evidence.sqlite3")
    )
    parser.add_argument("--out-dir", default=os.environ.get("RBTA_EVIDENCE_DIR"))
    parser.add_argument("--date", help="YYYY-MM-DD (WITA); default kemarin")
    parser.add_argument("--model-dir", help="direktori bundle model aktif (untuk model_version/sha256)")
    args = parser.parse_args()

    day = date.fromisoformat(args.date) if args.date else datetime.now(WITA).date() - timedelta(days=1)
    manager = DurableStateManager(args.state_file)
    out_dir = Path(args.out_dir) if args.out_dir else manager.filepath.parent / "evidence"
    identity = None
    if args.model_dir:
        model_dir = Path(args.model_dir)
        identity = {
            "version": json.loads((model_dir / "metadata.json").read_text(encoding="utf-8"))["model_version"],
            "sha256": hashlib.sha256((model_dir / "isolation_forest.joblib").read_bytes()).hexdigest(),
        }
    data = export_day(
        manager, Path(args.evidence_db), out_dir, day, identity, load_source_state(manager.history_db_path)
    )
    export_analyst_verdicts(manager, out_dir)
    print(json.dumps(data["summary"], indent=1, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
