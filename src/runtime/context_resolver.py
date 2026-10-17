from pathlib import Path
from typing import Any, Optional, Tuple

from fastapi import HTTPException

from src.model.scoring_pipeline import ScoringPipeline
from src.runtime.durable_state import DurableStateManager
from src.runtime.raw_evidence import RawAlertEvidenceStore
from src.runtime.replay_controller import ReplayController
from src.runtime.service import LiveRBTAService


class DashboardRuntimeResolver:
    """Menentukan konteks eksekusi operasional (live atau replay run) dengan aman."""

    def __init__(
        self,
        live_service: LiveRBTAService,
        live_evidence_store: RawAlertEvidenceStore,
        replay_controller: ReplayController,
        scoring_pipeline: ScoringPipeline,
        replay_runs_dir: Optional[Path] = None,
    ) -> None:
        self.live_service = live_service
        self.live_evidence_store = live_evidence_store
        self.replay_controller = replay_controller
        self.scoring_pipeline = scoring_pipeline
        self.replay_runs_dir = replay_runs_dir or Path("data/runtime/replay-runs").resolve()

    def resolve(self, run_id: Optional[str] = None) -> Tuple[LiveRBTAService, RawAlertEvidenceStore, str]:
        """Tentukan service, evidence store, dan mode konteks ('LIVE' atau 'REPLAY').

        Parameters
        ----------
        run_id : str | None
            Bila None, kembalikan runtime live. Selain itu, muat replay run yang dimaksud.

        Returns
        -------
        Tuple[LiveRBTAService, RawAlertEvidenceStore, str]
            (service, evidence_store, context_mode)
        """
        if not run_id or run_id.strip() == "":
            return self.live_service, self.live_evidence_store, "LIVE"

        clean_id = run_id.strip()

        # Cek dulu apakah ini run yang sedang aktif di replay_controller.
        if self.replay_controller.run_id == clean_id and self.replay_controller.current_service:
            return (
                self.replay_controller.current_service,
                self.replay_controller.current_evidence_store or self.live_evidence_store,
                "REPLAY",
            )

        # Lalu cek run yang tersimpan di disk.
        run_workspace = self.replay_runs_dir / clean_id
        if not run_workspace.exists() or not run_workspace.is_dir():
            raise HTTPException(status_code=404, detail=f"Replay run '{clean_id}' not found")

        state_file = run_workspace / "state.json"
        evidence_file = run_workspace / "raw_alert_evidence.sqlite3"

        if not state_file.exists() or not evidence_file.exists():
            raise HTTPException(status_code=404, detail=f"Replay run '{clean_id}' workspace is incomplete")

        state_mgr = DurableStateManager(state_file)
        evidence_store = RawAlertEvidenceStore(evidence_file)

        # Bangun ulang service read-only dari disk.
        service = LiveRBTAService(
            scoring_pipeline=self.scoring_pipeline,
            state_manager=state_mgr,
            raw_evidence_store=evidence_store,
            source_mode="REPLAY",
        )
        return service, evidence_store, "REPLAY"
