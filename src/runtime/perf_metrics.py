import time
import logging
from contextlib import contextmanager
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class ReplayPerfMetrics:
    """Instrumentasi performa ringan untuk pipeline replay RBTA.
    Mencatat waktu per tahap dan jumlah event dengan overhead minimal.
    """
    def __init__(self, report_interval: int = 1000, total_events: Optional[int] = None):
        self.report_interval = report_interval
        self.total_events = total_events
        
        # Metrik waktu (dalam detik, dikonversi ke ms saat dilaporkan).
        self.times = {
            "json_parse": 0.0,
            "canonicalize": 0.0,
            "raw_evidence": 0.0,
            "rbta_engine": 0.0,
            "scoring": 0.0,
            "state_persist": 0.0,
            "total_processing": 0.0,
        }
        
        # Counter
        self.counts = {
            "events_processed": 0,
            "meta_alerts_finalized": 0,
            "checkpoints_written": 0,
        }
        
        self.start_time = time.perf_counter()
        
    @contextmanager
    def stage(self, name: str):
        """Context manager untuk mengukur waktu satu tahap pipeline."""
        start = time.perf_counter()
        try:
            yield
        finally:
            elapsed = time.perf_counter() - start
            if name in self.times:
                self.times[name] += elapsed
            else:
                self.times[name] = elapsed
                
    def increment(self, counter: str, amount: int = 1):
        """Tambah counter sebesar nilai yang diberikan."""
        if counter in self.counts:
            self.counts[counter] += amount
        else:
            self.counts[counter] = amount
            
        if counter == "events_processed" and self.counts["events_processed"] % self.report_interval == 0:
            self.report()
            
    def summary(self) -> Dict[str, Any]:
        """Kembalikan dict semua metrik, dengan waktu dalam ms."""
        elapsed_seconds = time.perf_counter() - self.start_time
        events_processed = self.counts.get("events_processed", 0)
        
        events_per_second = events_processed / elapsed_seconds if elapsed_seconds > 0 else 0
        
        estimated_remaining_time = None
        if self.total_events is not None and events_processed > 0 and events_per_second > 0:
            remaining_events = max(0, self.total_events - events_processed)
            estimated_remaining_time = remaining_events / events_per_second

        result = {
            "counts": self.counts.copy(),
            "times_ms": {k: v * 1000 for k, v in self.times.items()},
            "derived": {
                "elapsed_seconds": elapsed_seconds,
                "events_per_second": events_per_second,
            }
        }
        
        if estimated_remaining_time is not None:
            result["derived"]["estimated_remaining_time_seconds"] = estimated_remaining_time
            
        return result
        
    def report(self):
        """Catat ringkasan saat ini di level INFO."""
        data = self.summary()
        derived = data["derived"]
        counts = data["counts"]
        times_ms = data["times_ms"]
        
        events = counts.get('events_processed', 0)
        eps = derived.get('events_per_second', 0)
        elapsed = derived.get('elapsed_seconds', 0)
        
        log_msg = (
            f"Perf Report: {events} events processed in {elapsed:.2f}s "
            f"({eps:.1f} events/sec)"
        )
        
        if "estimated_remaining_time_seconds" in derived:
            rem = derived["estimated_remaining_time_seconds"]
            log_msg += f" - ETA: {rem:.1f}s"
            
        logger.info(log_msg)
        
        # Catat rincian per tahap bila ada waktu yang tercatat.
        total_time = sum(times_ms.values()) - times_ms.get("total_processing", 0) # hindari terhitung dua kali bila total ikut masuk
        if total_time > 0:
            breakdown = ", ".join(f"{k}: {v:.1f}ms" for k, v in times_ms.items() if k != "total_processing" and v > 0)
            logger.info(f"Stage times: {breakdown}")
