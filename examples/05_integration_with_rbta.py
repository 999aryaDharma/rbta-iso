"""Contoh integrasi: stream → RBTA → evaluasi.

Simulasi real-time dengan bucketing RBTA dan evaluasi metrik
(tanpa IF — evaluasi batch di akhir).
"""

import sys
from datetime import datetime
from pathlib import Path

import pandas as pd

# Tambahkan path source.
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.streaming import AlertStreamSimulator
from engine.rbta_core import run_rbta


class RBTAStreamProcessor:
    """Pemrosesan RBTA real-time dari alert simulasi."""
    
    def __init__(self, lookback_sec=300):
        self.lookback_sec = lookback_sec
        self.alert_count = 0
        self.bucket_count = 0
        self.alerts_raw = []
    
    def process_alert(self, alert):
        """Terima alert dari simulator, antrekan untuk RBTA."""
        # Simpan raw alert untuk diproses RBTA.
        self.alerts_raw.append({
            'timestamp_utc': alert.get('timestamp_utc'),
            'agent_id': alert.get('agent_id'),
            'agent_name': alert.get('agent_name'),
            'rule_id': alert.get('rule_id'),
            'rule_group_primary': alert.get('rule_group_primary'),
            'rule_level': alert.get('rule_level'),
            'srcip': alert.get('srcip'),
            'mitre_tactic': alert.get('mitre_tactic'),
            'payload': alert.get('payload'),
        })
        
        self.alert_count += 1
        
        # Catat pemrosesan batch setiap 10k alert.
        if self.alert_count % 10000 == 0:
            print(f"[STREAM] Processed {self.alert_count:,} alerts, "
                  f"queued for RBTA")


def main():
    print("=" * 70)
    print("INTEGRATION 1: Stream → RBTA → Metrics")
    print("=" * 70)
    
    # Siapkan simulator.
    # speed_factor=100 berarti 100 detik nyata = 1 detik simulasi.
    # Timestamp tetap dipertahankan selama replay.
    sim = AlertStreamSimulator(
        csv_path="data/raw/rbta_ready_all.csv",
        speed_factor=100,           # dipercepat 100x
        log_file="output/05_stream_rbta.log",
        log_level="INFO",           # tampilkan progres
        log_frequency=10000,        # setiap 10k alert
    )
    
    # Siapkan processor.
    processor = RBTAStreamProcessor(lookback_sec=300)
    
    # Tahap 1: replay streaming.
    print("\n[PHASE 1] Streaming alerts through simulator...")
    start = datetime.now()
    stats = sim.replay(on_alert_callback=processor.process_alert)
    duration = (datetime.now() - start).total_seconds()
    
    print(f"\n✓ Streamed {processor.alert_count:,} alerts in {duration:.1f} sec")
    print(f"  Rate: {processor.alert_count/duration:.0f} alerts/sec")
    
    # Tahap 2: bucketing RBTA (mode batch di akhir).
    print(f"\n[PHASE 2] Converting to DataFrame and running RBTA...")
    
    # Ubah list dict menjadi DataFrame.
    df_alerts = pd.DataFrame(processor.alerts_raw)
    
    # Petakan nama kolom ke format yang diharapkan.
    df_alerts = df_alerts.rename(columns={
        'timestamp_utc': 'timestamp',
        'rule_group_primary': 'rule_groups',
        'rule_level': 'rule_level',
    })
    
    start = datetime.now()
    df_meta, df_compound, idx_map, elastic_win, wmark = run_rbta(
        df=df_alerts,
        delta_t_minutes=5,      # window dasar 5 menit
        max_window_minutes=60,  # maksimum 1 jam
        buffer_size=50,
    )
    duration = (datetime.now() - start).total_seconds()
    
    print(f"\n✓ RBTA produced {len(df_meta):,} buckets in {duration:.1f} sec")
    if len(df_meta) > 0:
        print(f"  Average alerts/bucket: {len(processor.alerts_raw)/len(df_meta):.1f}")
    
    # Tahap 3: ringkasan.
    print(f"\n[PHASE 3] Results:")
    print(f"  Raw alerts: {len(processor.alerts_raw):,}")
    print(f"  RBTA buckets: {len(df_meta):,}")
    if len(df_meta) > 0:
        print(f"  Compression: {len(processor.alerts_raw)/len(df_meta):.1f}x")
    
    # Contoh output.
    print(f"\n[SAMPLE] First 3 buckets:")
    for i, row in enumerate(df_meta.head(3).itertuples()):
        print(f"  Bucket {i+1}:")
        print(f"    - Agent: {row.agent_id}")
        print(f"    - Rule group: {row.rule_groups}")
        print(f"    - Alert count: {row.alert_count}")
        print(f"    - Severity: {row.rule_level}")
    
    print("\n" + "=" * 70)
    print("✓ INTEGRATION 1 Complete")
    print("=" * 70)


if __name__ == "__main__":
    main()
