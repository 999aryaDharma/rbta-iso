"""Replay alert lalu export ke JSON per baris untuk pemrosesan berikutnya.

Berguna untuk:
  - Menyimpan aliran ke file untuk dianalisis nanti
  - Integrasi dengan tool lain (jq, pandas, dll.)
  - Debugging & development
"""

import sys
import os
import json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.streaming import AlertStreamSimulator
import pandas as pd


def main():
    print("\n" + "="*80)
    print("EXAMPLE 2: Export Stream to JSONL")
    print("="*80 + "\n")
    
    export_path = "output/02_alerts_stream.jsonl"
    
    # Siapkan simulator dengan export aktif.
    sim = AlertStreamSimulator(
        csv_path="data/raw/rbta_ready_all.csv",
        speed_factor=100,
        log_file="output/02_export.log",
        log_level="INFO",
        log_frequency=10000,
        export_jsonl=True,
        export_path=export_path,
    )
    
    print(f"\nSimulating alerts dan exporting ke {export_path}...\n")
    stats = sim.replay()
    
    # Verifikasi hasil export.
    print("\n" + "-"*80)
    print("Verifying exported JSONL...")
    print("-"*80)
    
    line_count = 0
    with open(export_path, 'r') as f:
        for line in f:
            line_count += 1
            if line_count <= 3:
                # Cetak 3 baris pertama sebagai sampel.
                data = json.loads(line)
                print(f"\nLine {line_count} (sample):")
                print(f"  Agent: {data.get('agent_name')}")
                print(f"  Rule: {data.get('rule_group_primary')} (id={data.get('rule_id')})")
                print(f"  Severity: {data.get('rule_level')}")
                print(f"  Time: {data.get('timestamp_utc')}")
    
    print(f"\nTotal lines in JSONL: {line_count:,}")
    print(f"File size: {os.path.getsize(export_path) / (1024**2):.1f} MB")
    
    # Muat ke DataFrame untuk dianalisis.
    print("\n" + "-"*80)
    print("Loading JSONL to pandas DataFrame...")
    print("-"*80)
    
    df = pd.read_json(export_path, lines=True)
    print(f"\nDataFrame shape: {df.shape}")
    print(f"Columns: {list(df.columns)[:10]}...")
    print(f"Memory usage: {df.memory_usage(deep=True).sum() / (1024**2):.1f} MB")
    
    print("\n" + "="*80)
    print("EXPORT COMPLETE")
    print("="*80)
    print(f"Exported file: {export_path}")
    print(f"Total alerts: {stats.total_alerts:,}")
    print(f"Duration: {stats.duration_sec:.1f}s")
    print("="*80 + "\n")


if __name__ == "__main__":
    main()
