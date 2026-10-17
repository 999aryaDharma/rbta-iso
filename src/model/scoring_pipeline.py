"""Scoring pipeline Isolation Forest dan training reference."""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import subprocess
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler
import sklearn

from src.contracts.meta_alert import MetaAlert
from src.contracts.scored_meta_alert import ScoredMetaAlert
from src.features.extractor import FEATURE_COLUMNS, SevenFeatureExtractor
from src.model.calibration import ScoreCalibration
from src.model.decision import evaluate_decision
from src.model.threshold import TukeyThreshold, compute_tukey_threshold


@dataclass(frozen=True)
class ModelArtifactBundle:
    """Bundle in-memory berisi keenam komponen artefak model hasil training."""

    scaler: RobustScaler
    model: IsolationForest
    calibration: ScoreCalibration
    threshold: TukeyThreshold
    metadata: Dict[str, Any]
    schema: Dict[str, Any]


def train_reference_pipeline(
    metas: Sequence[MetaAlert],
    calibration_metas: Optional[Sequence[MetaAlert]] = None,
    random_state: int = 42,
    model_version: str = "rbta-if-v1",
    training_run_id: Optional[str] = None,
    git_commit: Optional[str] = None,
    research_config_hash: Optional[str] = None,
) -> ModelArtifactBundle:
    """Latih model Isolation Forest reference dan hasilkan bundle artefak terkalibrasi.

    Parameters
    ----------
    metas : Sequence[MetaAlert]
        Meta-alert reference untuk training.
    random_state : int
        Seed acak tetap demi reprodusibilitas.
    model_version : str
        ID versi model yang dilatih.
    training_run_id : str | None
        ID unik run training.
    git_commit : str | None
        SHA commit Git untuk reprodusibilitas penelitian.
    research_config_hash : str | None
        Hash kriptografis dari hyperparameter penelitian.

    Returns
    -------
    ModelArtifactBundle
        Bundle lengkap yang siap diserialisasi dan dipakai inferensi.
    """
    if len(metas) < 4:
        raise ValueError(f"At least 4 meta-alerts are required to train reference pipeline, got {len(metas)}")

    # Ekstrak 7 fitur kanonis sebagai DataFrame bernama kolom.
    X_df = SevenFeatureExtractor.extract_features_df(metas)

    # Fit RobustScaler.
    scaler = RobustScaler()
    scaler.fit(X_df)
    X_scaled = scaler.transform(X_df)

    # Fit IsolationForest (200 tree, contamination="auto").
    model = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=random_state,
        n_jobs=-1,
    )
    model.fit(X_scaled)

    # Skor kalibrasi diturunkan dari populasi lain yang lebih belakang bila tersedia.
    # Pemanggil lama tetap memakai populasi yang sama, tetapi orkestrasi penelitian
    # resmi selalu menyediakan set ini.
    calibration_population = list(calibration_metas) if calibration_metas is not None else list(metas)
    if len(calibration_population) < 4:
        raise ValueError(
            f"At least 4 meta-alerts are required for score calibration, got {len(calibration_population)}"
        )
    calibration_df = SevenFeatureExtractor.extract_features_df(calibration_population)
    calibration_scaled = scaler.transform(calibration_df)
    raw_scores = -model.score_samples(calibration_scaled)
    raw_min = float(np.min(raw_scores))
    raw_max = float(np.max(raw_scores))

    # Fit kalibrasi skor.
    calibration = ScoreCalibration(
        raw_min=raw_min,
        raw_max=raw_max,
        higher_is_more_anomalous=True,
        version="minmax-v1",
    )

    # Hitung skor terkalibrasi dan threshold Tukey IQR.
    cal_scores = [calibration.calibrate(float(s)) for s in raw_scores]
    threshold = compute_tukey_threshold(cal_scores)

    # Metadata dan skema.
    schema = {
        "schema_version": "1.0",
        "features": list(FEATURE_COLUMNS),
    }

    start_times = [m.start_time for m in metas if m.start_time is not None]
    end_times = [m.end_time for m in metas if m.end_time is not None]
    calibration_start_times = [m.start_time for m in calibration_population if m.start_time is not None]
    calibration_end_times = [m.end_time for m in calibration_population if m.end_time is not None]

    if git_commit is not None:
        resolved_git_commit = git_commit
    else:
        try:
            resolved_git_commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
        except Exception:
            resolved_git_commit = "unavailable"

    resolved_run_id = training_run_id or f"run_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"

    if research_config_hash is not None:
        resolved_config_hash = research_config_hash
    else:
        config_str = f"model_version={model_version},random_state={random_state},contamination=auto,n_estimators=200"
        resolved_config_hash = hashlib.sha256(config_str.encode("utf-8")).hexdigest()

    metadata = {
        "model_version": model_version,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "training_run_id": resolved_run_id,
        "python_version": sys.version,
        "sklearn_version": sklearn.__version__,
        "n_estimators": 200,
        "contamination": "auto",
        "random_state": random_state,
        "training_row_count": len(metas),
        "meta_alert_count": len(metas),
        "calibration_row_count": len(calibration_population),
        "validation_strategy": (
            "chronological_reference_calibration_test"
            if calibration_metas is not None
            else "same_population_legacy"
        ),
        "training_period_start": min(start_times).isoformat() if start_times else None,
        "training_period_end": max(end_times).isoformat() if end_times else None,
        "calibration_period_start": min(calibration_start_times).isoformat() if calibration_start_times else None,
        "calibration_period_end": max(calibration_end_times).isoformat() if calibration_end_times else None,
        "score_calibration_version": calibration.version,
        "git_commit": resolved_git_commit,
        "research_config_hash": resolved_config_hash,
        "feature_schema_version": schema["schema_version"],
    }

    return ModelArtifactBundle(
        scaler=scaler,
        model=model,
        calibration=calibration,
        threshold=threshold,
        metadata=metadata,
        schema=schema,
    )


def top_scaled_deviations(scaled_row: Sequence[float], k: int = 2) -> Tuple[Tuple[str, float], ...]:
    """k fitur dengan |nilai RobustScaler| terbesar (seri: urutan FEATURE_COLUMNS). Tidak memengaruhi skor."""
    order = sorted(range(len(FEATURE_COLUMNS)), key=lambda j: (-abs(float(scaled_row[j])), j))
    return tuple((FEATURE_COLUMNS[j], float(scaled_row[j])) for j in order[:k])


class ScoringPipeline:
    """Scoring pipeline inferensi yang hanya berjalan dalam mode prediksi (read-only)."""

    def __init__(self, bundle: ModelArtifactBundle) -> None:
        self.bundle: ModelArtifactBundle = bundle
        self.scaler: RobustScaler = bundle.scaler
        self.model: IsolationForest = bundle.model
        self.calibration: ScoreCalibration = bundle.calibration
        self.threshold: TukeyThreshold = bundle.threshold
        self.metadata: Dict[str, Any] = bundle.metadata
        self.schema: Dict[str, Any] = bundle.schema

        # Skema harus sesuai FEATURE_COLUMNS kanonis.
        schema_features = tuple(self.schema.get("features", []))
        if schema_features != FEATURE_COLUMNS:
            raise ValueError(f"Bundle feature schema {schema_features} != expected {FEATURE_COLUMNS}")

    def score_single(self, meta: MetaAlert) -> ScoredMetaAlert:
        """Skor satu event MetaAlert dalam mode stream/live tanpa fitting.

        Parameters
        ----------
        meta : MetaAlert
            DTO MetaAlert yang masuk.

        Returns
        -------
        ScoredMetaAlert
            DTO hasil skor yang immutable.
        """
        features_dict = SevenFeatureExtractor.extract_features_dict(meta)
        X_single_df = pd.DataFrame([features_dict], columns=list(FEATURE_COLUMNS))

        # Transform satu baris memakai scaler yang tersimpan.
        X_scaled = self.scaler.transform(X_single_df)

        # Hanya inferensi: score_samples.
        raw_score = float(-self.model.score_samples(X_scaled)[0])
        anomaly_score = float(self.calibration.calibrate(raw_score))

        decision, action, escalate = evaluate_decision(
            anomaly_score=anomaly_score,
            threshold=self.threshold.threshold,
            max_severity=meta.max_severity,
            alert_count=meta.alert_count,
            mitre_tactic_count=len(meta.mitre_tactics_unique),
        )

        return ScoredMetaAlert(
            meta_id=meta.meta_id,
            agent_id=meta.agent_id,
            agent_name=meta.agent_name,
            rule_group_primary=meta.rule_group_primary,
            start_time=meta.start_time,
            end_time=meta.end_time,
            alert_count=meta.alert_count,
            max_severity=meta.max_severity,
            mitre_tactics=meta.mitre_tactics_unique,
            seven_features=features_dict,
            raw_model_score=raw_score,
            anomaly_score=anomaly_score,
            threshold_used=self.threshold.threshold,
            decision=decision,
            action=action,
            escalate=escalate,
            model_version=str(self.metadata.get("model_version", "unknown")),
            feature_schema_version=str(self.schema.get("schema_version", "1.0")),
            score_calibration_version=str(self.calibration.version),
            source_alert_ids=meta.wazuh_alert_ids,
            top_deviations=top_scaled_deviations(X_scaled[0]),
        )

    def score_batch(self, metas: Sequence[MetaAlert]) -> List[ScoredMetaAlert]:
        """Skor sekumpulan event MetaAlert secara efisien.

        Parameters
        ----------
        metas : Sequence[MetaAlert]
            Batch DTO MetaAlert.

        Returns
        -------
        List[ScoredMetaAlert]
            Daftar DTO hasil skor immutable dengan urutan yang sama.
        """
        if not metas:
            return []
            
        features_dicts = [SevenFeatureExtractor.extract_features_dict(m) for m in metas]
        X_batch_df = pd.DataFrame(features_dicts, columns=list(FEATURE_COLUMNS))
        
        # Transform dan skor per batch.
        X_scaled = self.scaler.transform(X_batch_df)
        raw_scores = -self.model.score_samples(X_scaled)
        
        results = []
        for i, meta in enumerate(metas):
            raw_score = float(raw_scores[i])
            anomaly_score = float(self.calibration.calibrate(raw_score))
            
            decision, action, escalate = evaluate_decision(
                anomaly_score=anomaly_score,
                threshold=self.threshold.threshold,
                max_severity=meta.max_severity,
                alert_count=meta.alert_count,
                mitre_tactic_count=len(meta.mitre_tactics_unique),
            )
            
            results.append(
                ScoredMetaAlert(
                    meta_id=meta.meta_id,
                    agent_id=meta.agent_id,
                    agent_name=meta.agent_name,
                    rule_group_primary=meta.rule_group_primary,
                    start_time=meta.start_time,
                    end_time=meta.end_time,
                    alert_count=meta.alert_count,
                    max_severity=meta.max_severity,
                    mitre_tactics=meta.mitre_tactics_unique,
                    seven_features=features_dicts[i],
                    raw_model_score=raw_score,
                    anomaly_score=anomaly_score,
                    threshold_used=self.threshold.threshold,
                    decision=decision,
                    action=action,
                    escalate=escalate,
                    model_version=str(self.metadata.get("model_version", "unknown")),
                    feature_schema_version=str(self.schema.get("schema_version", "1.0")),
                    score_calibration_version=str(self.calibration.version),
                    source_alert_ids=meta.wazuh_alert_ids,
                    top_deviations=top_scaled_deviations(X_scaled[i]),
                )
            )
            
        return results

    def score_meta_alerts(
        self,
        metas: Sequence[MetaAlert],
    ) -> Tuple[pd.DataFrame, List[ScoredMetaAlert]]:
        """Skor sekumpulan MetaAlert dalam mode batch.

        Parameters
        ----------
        metas : Sequence[MetaAlert]
            Urutan DTO MetaAlert.

        Returns
        -------
        Tuple[pd.DataFrame, List[ScoredMetaAlert]]
            DataFrame hasil skor beserta daftar objek ScoredMetaAlert yang sesuai.
        """
        scored_list = self.score_batch(metas)
        rows = [
            {
                "meta_id": s.meta_id,
                "agent_id": s.agent_id,
                "agent_name": s.agent_name,
                "rule_group_primary": s.rule_group_primary,
                "start_time": s.start_time,
                "end_time": s.end_time,
                "alert_count": s.alert_count,
                "max_severity": s.max_severity,
                "raw_model_score": s.raw_model_score,
                "anomaly_score": s.anomaly_score,
                "threshold_used": s.threshold_used,
                "decision": s.decision,
                "action": s.action,
                "escalate": s.escalate,
                "model_version": s.model_version,
                **dict(s.seven_features),
            }
            for s in scored_list
        ]
        df_scored = pd.DataFrame(rows)
        return df_scored, scored_list
