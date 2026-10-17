"""Contoh paling sederhana: muat CSV, replay alert dengan logging, selesai.

Berguna untuk:
  - Memahami dataset
  - Validasi cepat
  - Menghasilkan log replay untuk dokumentasi
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.streaming import AlertStreamSimulator


def main():
    print("\n" + "="*80)
    print("EXAMPLE 1: Basic Alert Stream Replay")
    print("="*80 + "\n")
    
    # Siapkan simulator.
    sim = AlertStreamSimulator(
        csv_path="data/raw/rbta_ready_all.csv",
        speed_factor=100,  # dipercepat 100x
        log_file="output/01_replay.log",
        log_level="INFO",
        log_frequency=5000,  # log setiap 5000 alert
    )
    
    # Daftarkan callback sederhana (hanya menghitung).
    count = [0]
    def count_alerts(alert):
        count[0] += 1
    
    sim.on_alert(count_alerts)
    
    # Jalankan simulasi.
    print("\nStarting replay...\n")
    stats = sim.replay()
    
    # Cetak ringkasan.
    print("\n" + "="*80)
    print("SIMULATION SUMMARY")
    print("="*80)
    print(f"Total alerts: {stats.total_alerts:,}")
    print(f"Duration: {stats.duration_sec:.1f}s")
    print(f"Rate: {stats.alerts_per_sec:.0f} alerts/sec")
    print(f"Callback verified: {count[0]:,} alerts processed")
    print(f"\nLog file: output/01_replay.log")
    print("="*80 + "\n")


if __name__ == "__main__":
    main()
