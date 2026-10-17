"""Emulator aliran alert real-time dari dataset CSV statis.

Fitur:
  - Replay dengan jeda waktu yang akurat dan bisa dipercepat
  - Logging untuk memantau simulasi
  - Callback untuk pemrosesan real-time
  - Statistik isi aliran

Contoh:
  sim = AlertStreamSimulator(
      csv_path="data/raw/rbta_ready_all.csv",
      speed_factor=100
  )
  sim.on_alert(lambda alert: process(alert))
  sim.replay()
"""

import logging
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Optional
from pathlib import Path

import pandas as pd

log = logging.getLogger(__name__)



@dataclass
class StreamStats:
    """Pengumpul statistik untuk simulasi streaming."""
    total_alerts: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    agent_counts: dict = field(default_factory=dict)
    rule_group_counts: dict = field(default_factory=dict)
    severity_counts: dict = field(default_factory=dict)
    mitre_coverage: int = 0

    def add_alert(self, alert: pd.Series) -> None:
        """Perbarui statistik dengan alert baru."""
        self.total_alerts += 1

        # Distribusi agent.
        agent = str(alert.get("agent_name", "unknown")).strip()
        self.agent_counts[agent] = self.agent_counts.get(agent, 0) + 1

        # Distribusi rule group.
        rg = str(alert.get("rule_group_primary", "unknown")).strip()
        self.rule_group_counts[rg] = self.rule_group_counts.get(rg, 0) + 1

        # Distribusi severity.
        sev = int(alert.get("rule_level", 1))
        sev_bucket = self._severity_bucket(sev)
        self.severity_counts[sev_bucket] = self.severity_counts.get(sev_bucket, 0) + 1

        # Cakupan MITRE.
        if pd.notna(alert.get("mitre_tactic")) and str(alert.get("mitre_tactic")).strip():
            self.mitre_coverage += 1

    @staticmethod
    def _severity_bucket(level: int) -> str:
        """Kelompokkan severity ke kategori."""
        if level <= 2:
            return "1-2_Info"
        elif level <= 4:
            return "3-4_Medium"
        elif level <= 6:
            return "5-6_High"
        else:
            return "7+_Critical"

    @property
    def duration_sec(self) -> float:
        """Durasi simulasi dalam detik."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0

    @property
    def alerts_per_sec(self) -> float:
        """Throughput (alert/detik)."""
        dur = self.duration_sec
        if dur > 0:
            return self.total_alerts / dur
        return 0.0



def setup_stream_logger(
    log_file: Optional[str] = None,
    log_level: str = "INFO",
) -> logging.Logger:
    """Siapkan logger untuk simulasi streaming."""
    logger = logging.getLogger("AlertStreamSimulator")
    logger.setLevel(getattr(logging, log_level.upper()))

    # Handler console.
    ch = logging.StreamHandler()
    ch.setLevel(getattr(logging, log_level.upper()))
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # Handler file (bila ditentukan).
    if log_file:
        os.makedirs(os.path.dirname(log_file) if os.path.dirname(log_file) else ".", exist_ok=True)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(getattr(logging, log_level.upper()))
        fh.setFormatter(formatter)
        logger.addHandler(fh)
        logger.info("Logging to file: %s", log_file)

    return logger



class AlertStreamSimulator:
    """Simulator streaming alert real-time dari CSV statis.

    Fitur:
      - Muat CSV dan urutkan menurut timestamp
      - Replay dengan jeda waktu yang akurat (dipercepat)
      - Callback untuk setiap alert
      - Logging dengan pelacakan progres
      - Ringkasan statistik di akhir
    """

    def __init__(
        self,
        csv_path: str = "data/raw/rbta_ready_all.csv",
        speed_factor: float = 100.0,
        log_file: Optional[str] = None,
        log_level: str = "INFO",
        log_frequency: int = 1000,
        filter_agents: Optional[list[str]] = None,
        filter_severity_min: Optional[int] = None,
        export_jsonl: bool = False,
        export_path: Optional[str] = None,
    ):
        """Parameters
        ----------
        csv_path : str
            Path ke data alert CSV mentah
        speed_factor : float
            Pengali kecepatan (100 = 100x lebih cepat)
        log_file : str, optional
            Path file log output
        log_level : str
            Level log (DEBUG, INFO, WARNING, ERROR)
        log_frequency : int
            Catat progres setiap N alert
        filter_agents : list, optional
            Bila diisi, hanya replay alert dari agent ini
        filter_severity_min : int, optional
            Bila diisi, hanya replay alert dengan severity >= nilai ini
        export_jsonl : bool
            Sekaligus export alert ke format JSONL
        export_path : str, optional
            Path JSONL hasil export (bila export_jsonl=True)
        """
        self.csv_path = csv_path
        self.speed_factor = speed_factor
        self.log_frequency = log_frequency
        self.filter_agents = filter_agents
        self.filter_severity_min = filter_severity_min
        self.export_jsonl = export_jsonl
        self.export_path = export_path or "output/alerts_stream.jsonl"

        self.logger = setup_stream_logger(log_file, log_level)
        self.df = None
        self.callback = None
        self.stats = StreamStats()
        self._export_file = None

    def load_data(self) -> int:
        """Muat dan praproses data CSV."""
        self.logger.info("Loading CSV data: %s", self.csv_path)

        if not os.path.exists(self.csv_path):
            self.logger.error("CSV file not found: %s", self.csv_path)
            raise FileNotFoundError(f"CSV file not found: {self.csv_path}")

        file_size_mb = os.path.getsize(self.csv_path) / (1024 ** 2)
        self.logger.info("File size: %.2f MB", file_size_mb)

        try:
            self.df = pd.read_csv(self.csv_path)
        except Exception as e:
            self.logger.error("Failed to load CSV: %s", e)
            raise

        # Parse timestamp.
        try:
            self.df["timestamp_utc"] = pd.to_datetime(
                self.df["timestamp_utc"], errors="coerce"
            )
        except Exception as e:
            self.logger.warning("Failed to parse timestamps: %s", e)
            self.df["timestamp_utc"] = pd.NaT

        # Urutkan menurut timestamp.
        self.df = self.df.sort_values("timestamp_utc").reset_index(drop=True)

        n_raw = len(self.df)
        self.logger.info("Loaded %d raw alerts", n_raw)

        # Terapkan filter.
        if self.filter_agents:
            mask_agent = self.df["agent_name"].isin(self.filter_agents)
            self.df = self.df[mask_agent]
            self.logger.info("  Filter agents=%s: %d alerts remain",
                           self.filter_agents, len(self.df))

        if self.filter_severity_min is not None:
            mask_sev = self.df["rule_level"] >= self.filter_severity_min
            self.df = self.df[mask_sev]
            self.logger.info("  Filter severity >= %d: %d alerts remain",
                           self.filter_severity_min, len(self.df))

        n_filtered = len(self.df)
        if n_filtered < n_raw:
            self.logger.info("After filtering: %d alerts (%.1f%% of original)",
                           n_filtered, n_filtered / n_raw * 100)

        # Info rentang tanggal.
        t_min = self.df["timestamp_utc"].min()
        t_max = self.df["timestamp_utc"].max()
        if pd.notna(t_min) and pd.notna(t_max):
            duration_min = (t_max - t_min).total_seconds() / 60
            self.logger.info("Date range: %s to %s (%.1f minutes)",
                           t_min, t_max, duration_min)
            sim_duration_sec = duration_min * 60 / self.speed_factor
            self.logger.info("Simulation will take ~%.1f seconds at %.0fx speed",
                           sim_duration_sec, self.speed_factor)

        # Keragaman agent & rule_group.
        n_agents = self.df["agent_name"].nunique()
        n_rulegroups = self.df["rule_group_primary"].nunique()
        self.logger.info("Alert diversity: %d unique agents, %d unique rule groups",
                       n_agents, n_rulegroups)

        return n_filtered

    def on_alert(self, callback: Callable[[pd.Series], None]) -> None:
        """Daftarkan callback untuk setiap alert yang di-replay."""
        self.callback = callback
        self.logger.debug("Callback registered: %s", callback.__name__)

    def replay(self) -> StreamStats:
        """Loop simulasi utama — replay semua alert dengan jeda waktu yang akurat."""
        if self.df is None:
            n = self.load_data()
        else:
            n = len(self.df)

        if n == 0:
            self.logger.warning("No alerts to replay after filtering")
            return self.stats

        # Siapkan export.
        if self.export_jsonl:
            os.makedirs(os.path.dirname(self.export_path) or ".", exist_ok=True)
            self._export_file = open(self.export_path, "w", encoding="utf-8")
            self.logger.info("Exporting to JSONL: %s", self.export_path)

        # Cetak header.
        self.logger.info("=" * 80)
        self.logger.info("  ALERT STREAM SIMULATION — STARTING")
        self.logger.info("=" * 80)
        self.logger.info("Total alerts: %d", n)
        self.logger.info("Speed factor: %.0fx", self.speed_factor)
        self.logger.info("Callbacks: %s", "enabled" if self.callback else "disabled")
        self.logger.info("-" * 80)

        self.stats.start_time = datetime.now()
        t_base = self.df.iloc[0]["timestamp_utc"]
        t_start_wall = time.perf_counter()
        last_log_idx = 0
        last_log_wall = t_start_wall

        try:
            for idx, (_, alert) in enumerate(self.df.iterrows(), 1):
                # Hitung jeda.
                t_alert = alert.get("timestamp_utc")
                if pd.notna(t_alert) and pd.notna(t_base):
                    delay_sec = (t_alert - t_base).total_seconds() / self.speed_factor
                    elapsed_wall = time.perf_counter() - t_start_wall
                    sleep_time = delay_sec - elapsed_wall
                    if sleep_time > 0:
                        time.sleep(sleep_time)

                # Callback.
                if self.callback:
                    try:
                        self.callback(alert)
                    except Exception as e:
                        self.logger.error("Callback failed for alert %d: %s", idx, e)

                # Export.
                if self._export_file:
                    try:
                        alert_dict = alert.to_dict()
                        # Ubah tipe yang tidak bisa diserialisasi.
                        for k, v in alert_dict.items():
                            if pd.isna(v):
                                alert_dict[k] = None
                            elif isinstance(v, (pd.Timestamp, datetime)):
                                alert_dict[k] = str(v)

                        import json
                        self._export_file.write(json.dumps(alert_dict) + "\n")
                    except Exception as e:
                        self.logger.warning("Failed to export alert %d: %s", idx, e)

                # Perbarui statistik.
                self.stats.add_alert(alert)

                # Logging & progres.
                if idx % self.log_frequency == 0 or idx == n:
                    t_now_wall = time.perf_counter()
                    elapsed_wall = t_now_wall - t_start_wall
                    rate = (idx - last_log_idx) / (t_now_wall - last_log_wall)

                    pct = idx / n * 100
                    eta_sec = (n - idx) / rate if rate > 0 else 0

                    self.logger.info(
                        "[PROGRESS] %d / %d alerts (%.1f%%) | %.0f alerts/sec | ETA: %.1fs",
                        idx, n, pct, rate, eta_sec
                    )

                    # Snapshot distribusi agent.
                    top_agents = sorted(
                        self.stats.agent_counts.items(),
                        key=lambda x: x[1],
                        reverse=True
                    )[:5]
                    agent_str = " | ".join([f"{a}:{c}" for a, c in top_agents])
                    self.logger.debug("  Top agents: %s", agent_str)

                    # Snapshot rule group.
                    top_rulegroups = sorted(
                        self.stats.rule_group_counts.items(),
                        key=lambda x: x[1],
                        reverse=True
                    )[:5]
                    rg_str = " | ".join([f"{rg}:{c}" for rg, c in top_rulegroups])
                    self.logger.debug("  Top rule groups: %s", rg_str)

                    last_log_idx = idx
                    last_log_wall = t_now_wall

        finally:
            if self._export_file:
                self._export_file.close()
                self.logger.info("Export file closed: %s", self.export_path)

        self.stats.end_time = datetime.now()

        # Cetak ringkasan.
        self._print_summary()

        return self.stats

    def _print_summary(self) -> None:
        """Cetak ringkasan detail di akhir replay."""
        self.logger.info("=" * 80)
        self.logger.info("  ALERT STREAM SIMULATION — COMPLETED")
        self.logger.info("=" * 80)

        self.logger.info("Total alerts processed: %d", self.stats.total_alerts)
        self.logger.info("Wall-clock duration: %.1f seconds", self.stats.duration_sec)
        self.logger.info("Processing rate: %.0f alerts/sec", self.stats.alerts_per_sec)
        self.logger.info("")

        # Distribusi agent.
        self.logger.info("Agent distribution:")
        for agent, count in sorted(
            self.stats.agent_counts.items(),
            key=lambda x: x[1],
            reverse=True
        ):
            pct = count / self.stats.total_alerts * 100
            self.logger.info("  %-20s: %6d (%.1f%%)", agent, count, pct)

        self.logger.info("")

        # Distribusi rule group.
        self.logger.info("Alert type distribution (rule_group):")
        for rg, count in sorted(
            self.stats.rule_group_counts.items(),
            key=lambda x: x[1],
            reverse=True
        ):
            pct = count / self.stats.total_alerts * 100
            self.logger.info("  %-20s: %6d (%.1f%%)", rg, count, pct)

        self.logger.info("")

        # Distribusi severity.
        self.logger.info("Severity distribution:")
        for sev_bucket, count in sorted(self.stats.severity_counts.items()):
            pct = count / self.stats.total_alerts * 100
            self.logger.info("  %-15s: %6d (%.1f%%)", sev_bucket, count, pct)

        self.logger.info("")

        # Cakupan MITRE.
        mitre_pct = self.stats.mitre_coverage / self.stats.total_alerts * 100
        self.logger.info("MITRE ATT&CK coverage: %d alerts (%.1f%%)",
                       self.stats.mitre_coverage, mitre_pct)

        self.logger.info("=" * 80)

    def get_statistics(self) -> StreamStats:
        """Kembalikan statistik yang terkumpul."""
        return self.stats



if __name__ == "__main__":
    # Contoh: replay dasar dengan logging.
    sim = AlertStreamSimulator(
        csv_path="data/raw/rbta_ready_all.csv",
        speed_factor=100,
        log_file="output/stream_simulation.log",
        log_level="INFO",
        log_frequency=5000,
    )

    # Callback sederhana untuk menghitung.
    alert_count = [0]
    def simple_callback(alert):
        alert_count[0] += 1

    sim.on_alert(simple_callback)
    stats = sim.replay()

    print("\n" + "=" * 80)
    print(f"Simulation complete: {stats.total_alerts} alerts in {stats.duration_sec:.1f}s")
    print("=" * 80)
