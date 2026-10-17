#!/usr/bin/env python3
import argparse
import json
import logging
import os
import tracemalloc
from datetime import datetime, timedelta, timezone
from pathlib import Path
import time
import sys

# Pastikan root proyek ada di sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.etl.wazuh_canonicalizer import canonicalize_wazuh_alert
from src.runtime.service import LiveRBTAService
from src.runtime.durable_state import DurableStateManager
from src.runtime.raw_evidence import RawAlertEvidenceStore
from src.runtime.perf_metrics import ReplayPerfMetrics
from src.model.scoring_pipeline import ScoringPipeline, train_reference_pipeline
from src.contracts.meta_alert import MetaAlert
from src.contracts.raw_alert import CanonicalRawAlert

logger = logging.getLogger(__name__)

def create_dummy_bundle():
    """Buat ModelArtifactBundle dummy agar ScoringPipeline bisa dibuat."""
    base_t = datetime.now(timezone.utc)
    dummy_metas = [
        MetaAlert(
            meta_id=i,
            agent_id=f"00{1 + (i % 4)}",
            agent_name="soc-1",
            rule_group_primary="pam" if i % 2 == 0 else "authentication_failed",
            start_time=base_t + timedelta(minutes=i * 15),
            end_time=base_t + timedelta(minutes=i * 15 + 1),
            alert_count=1 + i * 2,
            max_severity=2 + (i % 12),
            rule_id_distribution={"5501": 1 + i, "5502": i},
            severity_distribution={2 + (i % 12): 1 + i},
            agent_criticality=1 + (i % 3),
            wazuh_alert_ids=(f"alert_{i}",),
            mitre_tactics_unique=("credential-access",) if i % 2 == 0 else (),
            critical_mitre_present=(i % 3 == 0),
            metadata={},
        )
        for i in range(1, 25)
    ]
    return train_reference_pipeline(dummy_metas, random_state=42, model_version="benchmark-v1")


def run_benchmark(dataset_path: Path, output_dir: Path):
    if not dataset_path.exists():
        logger.error(f"Dataset {dataset_path} does not exist.")
        sys.exit(1)
        
    output_dir.mkdir(parents=True, exist_ok=True)
    state_file = output_dir / "state.json"
    sqlite_file = output_dir / "raw_alert_evidence.sqlite3"
    
    # Hapus file lama bila ada.
    if state_file.exists():
        state_file.unlink()
    if sqlite_file.exists():
        sqlite_file.unlink()

    logger.info("Initializing components...")
    
    # Baca semua baris dulu untuk menghitung total event.
    with open(dataset_path, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]
    total_events = len(lines)
    
    bundle = create_dummy_bundle()
    scoring_pipeline = ScoringPipeline(bundle)
    
    state_manager = DurableStateManager(state_file)
    raw_evidence_store = RawAlertEvidenceStore(sqlite_file)
    
    # auto_persist dimatikan dan checkpoint dilakukan eksplisit, supaya waktu
    # state_persist_ms bisa diukur terpisah dari proses ingest.
    service = LiveRBTAService(
        scoring_pipeline=scoring_pipeline,
        state_manager=state_manager,
        base_delta_t=timedelta(minutes=15),
        adaptive=False,
        raw_evidence_store=raw_evidence_store,
        source_mode="REPLAY",
        auto_persist=False,
    )
    
    metrics = ReplayPerfMetrics(report_interval=1000, total_events=total_events)
    
    logger.info(f"Starting benchmark on {dataset_path} ({total_events} events)...")
    
    tracemalloc.start()
    benchmark_start_time = time.perf_counter()
    
    for line in lines:
        with metrics.stage("total_processing"):
            with metrics.stage("json_parse"):
                raw_data = json.loads(line)
            
            with metrics.stage("canonicalize"):
                canonical_alert = canonicalize_wazuh_alert(raw_data)
                
            # Ukur waktu raw evidence store.
            with metrics.stage("raw_evidence"):
                raw_evidence_store.store(canonical_alert, source_mode="REPLAY")
                
            with metrics.stage("rbta_engine"):
                finalized_metas = service.engine.process(canonical_alert)
                if finalized_metas:
                    service.pending_scoring.extend(finalized_metas)
                    
            with metrics.stage("scoring"):
                # Skor meta-alert yang tertunda.
                scored = []
                while service.pending_scoring:
                    meta = service.pending_scoring.pop(0)
                    scored_meta = service.scoring_pipeline.score_single(meta)
                    service.outbox.append(scored_meta)
                    service.finalized_history.append(scored_meta)
                    scored.append(scored_meta)
                    metrics.increment("meta_alerts_finalized")

        metrics.increment("events_processed")
        
        # Checkpoint durable berkala (setiap 500 event).
        if metrics.counts["events_processed"] % 500 == 0:
            with metrics.stage("state_persist"):
                service.checkpoint()
            metrics.increment("checkpoints_written")
            
    # Drain di akhir.
    with metrics.stage("total_processing"):
        with metrics.stage("rbta_engine"):
            drained_metas = service.engine.drain()
            if drained_metas:
                service.pending_scoring.extend(drained_metas)
                
        with metrics.stage("scoring"):
            while service.pending_scoring:
                meta = service.pending_scoring.pop(0)
                scored_meta = service.scoring_pipeline.score_single(meta)
                service.outbox.append(scored_meta)
                service.finalized_history.append(scored_meta)
                metrics.increment("meta_alerts_finalized")
                
        with metrics.stage("state_persist"):
            service.checkpoint()
        metrics.increment("checkpoints_written")
        
    benchmark_end_time = time.perf_counter()
    current, peak_ram = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    total_runtime = benchmark_end_time - benchmark_start_time
    events_per_sec = total_events / total_runtime if total_runtime > 0 else 0
    
    state_size = state_file.stat().st_size if state_file.exists() else 0
    sqlite_size = sqlite_file.stat().st_size if sqlite_file.exists() else 0
    
    results = {
        "dataset": str(dataset_path),
        "total_events": total_events,
        "total_runtime_seconds": total_runtime,
        "events_per_second": events_per_sec,
        "peak_ram_mb": peak_ram / (1024 * 1024),
        "state_json_size_bytes": state_size,
        "sqlite_db_size_bytes": sqlite_size,
        "metrics": metrics.summary()
    }
    
    print(json.dumps(results, indent=2))
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Benchmark RBTA replay pipeline.")
    parser.add_argument("--dataset", type=str, required=True, help="Path to JSONL dataset")
    parser.add_argument("--output-dir", type=str, required=True, help="Directory for output files")
    
    args = parser.parse_args()
    
    # Konfigurasi logging minimal untuk script ini.
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    
    run_benchmark(Path(args.dataset).resolve(), Path(args.output_dir).resolve())
