"""Unit test orkestrator ETL json_orches, memastikan tidak bergantung pada path tertentu."""
import json
from pathlib import Path
import pytest
from src.etl.json_orches import main


def test_json_orches_runs_with_custom_tmp_path(tmp_path: Path):
    """json_orches bisa memproses struktur direktori di dalam path sementara."""
    # Bangun struktur direktori tiruan: base_dir / 2026 / 08 / hasil_json / alert.json
    year_dir = tmp_path / "2026"
    month_dir = year_dir / "08"
    hasil_dir = month_dir / "hasil_json"
    hasil_dir.mkdir(parents=True, exist_ok=True)

    sample_alert = {
        "id": "1787895525.48425",
        "timestamp": "2026-08-28T05:38:45.712+0000",
        "agent": {"id": "001", "name": "soc-1"},
        "rule": {
            "id": "5501",
            "level": 3,
            "groups": ["pam"],
            "description": "PAM authentication succeeded",
            "mitre": {"tactic": ["Initial Access"]},
        },
        "data": {"srcip": "192.168.1.50"},
    }

    alert_file = hasil_dir / "sample_alert.json"
    alert_file.write_text(json.dumps(sample_alert) + "\n", encoding="utf-8")

    # Jalankan main dengan tmp_path.
    main(base_dir=tmp_path)

    # Cek file yang dihasilkan di tmp_path.
    month_csv = month_dir / "rbta_ready_2026_08.csv"
    final_csv = tmp_path / "rbta_ready_ALL.csv"
    report_file = tmp_path / "data_quality_report.txt"

    assert month_csv.exists(), f"Expected month CSV {month_csv} was not created"
    assert final_csv.exists(), f"Expected final CSV {final_csv} was not created"
    assert report_file.exists(), f"Expected quality report {report_file} was not created"
