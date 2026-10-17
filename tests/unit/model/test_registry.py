"""Unit test ModelArtifactRegistry dan publikasi staging yang atomik."""
from datetime import datetime, timezone
from pathlib import Path
import pytest

from src.contracts.meta_alert import MetaAlert
from src.model.registry import ModelRegistryError, ModelRegistry
from src.model.scoring_pipeline import train_reference_pipeline


def make_meta(meta_id: int) -> MetaAlert:
    count = (meta_id % 10) + 1
    max_sev = (meta_id % 14) + 1
    mitre = ("Execution",) if meta_id % 3 == 0 else ()
    return MetaAlert(
        meta_id=meta_id,
        agent_id="001",
        agent_name="soc-1",
        rule_group_primary="pam",
        start_time=datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc),
        end_time=datetime(2026, 8, 28, 10, 5, 0, tzinfo=timezone.utc),
        alert_count=count,
        max_severity=max_sev,
        rule_id_distribution={"5501": count},
        severity_distribution={max_sev: count},
        mitre_tactics_unique=mitre,
        critical_mitre_present=len(mitre) > 0,
        agent_criticality=(meta_id % 4) + 1,
        wazuh_alert_ids=(str(meta_id),),
    )


def test_registry_atomic_publish_and_load_roundtrip(tmp_path: Path):
    """Registry memublikasikan bundle secara atomik dari staging dan memuat bundle valid dengan parameter yang persis."""
    metas = [make_meta(i) for i in range(1, 40)]
    bundle = train_reference_pipeline(metas, random_state=42, model_version="rbta-if-test-v1")

    registry = ModelRegistry(base_dir=tmp_path)
    published_path = registry.publish_bundle(bundle, model_version="rbta-if-test-v1")

    assert published_path.exists()
    assert (published_path / "isolation_forest.joblib").exists()
    assert (published_path / "robust_scaler.joblib").exists()
    assert (published_path / "score_calibration.json").exists()
    assert (published_path / "threshold.json").exists()
    assert (published_path / "feature_schema.json").exists()
    assert (published_path / "metadata.json").exists()

    # Muat bundle dari registry.
    loaded_bundle = registry.load_bundle("rbta-if-test-v1")
    assert loaded_bundle.model.n_estimators == bundle.model.n_estimators
    assert loaded_bundle.calibration.raw_min == bundle.calibration.raw_min
    assert loaded_bundle.calibration.raw_max == bundle.calibration.raw_max
    assert loaded_bundle.threshold.threshold == bundle.threshold.threshold
    assert loaded_bundle.metadata["model_version"] == "rbta-if-test-v1"


def test_registry_missing_artifact_fails_fast(tmp_path: Path):
    """Bila salah satu dari 6 file artefak wajib hilang, pemuatan gagal dengan ModelRegistryError."""
    metas = [make_meta(i) for i in range(1, 40)]
    bundle = train_reference_pipeline(metas, random_state=42, model_version="v_incomplete")

    registry = ModelRegistry(base_dir=tmp_path)
    published_path = registry.publish_bundle(bundle, model_version="v_incomplete")

    # Hapus score_calibration.json.
    (published_path / "score_calibration.json").unlink()

    with pytest.raises(ModelRegistryError, match="Missing required artifact"):
        registry.load_bundle("v_incomplete")


def test_registry_feature_schema_mismatch_fails(tmp_path: Path):
    """Bila feature_schema.json tidak sesuai FEATURE_COLUMNS kanonis, pemuatan gagal dengan ModelRegistryError."""
    metas = [make_meta(i) for i in range(1, 40)]
    bundle = train_reference_pipeline(metas, random_state=42, model_version="v_bad_schema")

    registry = ModelRegistry(base_dir=tmp_path)
    published_path = registry.publish_bundle(bundle, model_version="v_bad_schema")

    # Rusak feature_schema.json.
    schema_file = published_path / "feature_schema.json"
    schema_file.write_text('{"schema_version": "1.0", "features": ["bad_feature"]}', encoding="utf-8")

    with pytest.raises(ModelRegistryError, match="Feature schema mismatch"):
        registry.load_bundle("v_bad_schema")


def test_registry_manifest_created_and_verified(tmp_path: Path):
    """manifest.json dibuat dengan hash SHA-256 dan file yang dirusak membuat pemuatan gagal."""
    metas = [make_meta(i) for i in range(1, 40)]
    bundle = train_reference_pipeline(metas, random_state=42, model_version="v_manifest")

    registry = ModelRegistry(base_dir=tmp_path)
    published_path = registry.publish_bundle(bundle, model_version="v_manifest")

    manifest_file = published_path / "manifest.json"
    assert manifest_file.exists()

    # Rusak satu file untuk memicu checksum yang tidak cocok.
    score_file = published_path / "score_calibration.json"
    score_file.write_text('{"corrupted": true}', encoding="utf-8")

    with pytest.raises(ModelRegistryError, match="Checksum mismatch"):
        registry.load_bundle("v_manifest")


def test_registry_explicit_version(tmp_path: Path):
    """Pemilihan explicit_version berfungsi dan menunjuk ke direktori yang tidak ada mengembalikan None."""
    metas = [make_meta(i) for i in range(1, 40)]
    bundle = train_reference_pipeline(metas, random_state=42, model_version="v_explicit_1")

    registry = ModelRegistry(base_dir=tmp_path)
    registry.publish_bundle(bundle, model_version="v_explicit_1")
    registry.publish_bundle(bundle, model_version="v_explicit_2")

    registry_explicit = ModelRegistry(base_dir=tmp_path, explicit_version="v_explicit_1")
    assert registry_explicit.get_active_version() == "v_explicit_1"

    registry_missing = ModelRegistry(base_dir=tmp_path, explicit_version="v_non_existent")
    assert registry_missing.get_active_version() is None


def test_registry_metadata_contains_reproducibility_fields(tmp_path: Path):
    """Metadata memuat git_commit, research_config_hash, feature_schema_version, training_run_id."""
    metas = [make_meta(i) for i in range(1, 40)]
    bundle = train_reference_pipeline(
        metas,
        random_state=42,
        model_version="v_meta",
        training_run_id="test_run_123",
        git_commit="a" * 40,
        research_config_hash="b" * 64,
    )

    assert bundle.metadata["training_run_id"] == "test_run_123"
    assert bundle.metadata["git_commit"] == "a" * 40
    assert bundle.metadata["research_config_hash"] == "b" * 64
    assert bundle.metadata["feature_schema_version"] == "1.0"


def test_registry_missing_manifest_fails_load(tmp_path: Path):
    """Memuat bundle tanpa manifest.json harus gagal dengan ModelRegistryError."""
    metas = [make_meta(i) for i in range(1, 40)]
    bundle = train_reference_pipeline(metas, random_state=42, model_version="v_no_manifest")

    registry = ModelRegistry(base_dir=tmp_path)
    published_path = registry.publish_bundle(bundle, model_version="v_no_manifest")

    # Hapus manifest.json.
    (published_path / "manifest.json").unlink()

    with pytest.raises(ModelRegistryError, match="Missing mandatory manifest"):
        registry.load_bundle("v_no_manifest")


def test_registry_incomplete_manifest_keys_fails(tmp_path: Path):
    """Memuat bundle dengan key manifest.json yang tidak lengkap harus gagal."""
    metas = [make_meta(i) for i in range(1, 40)]
    bundle = train_reference_pipeline(metas, random_state=42, model_version="v_incomplete_manifest")

    registry = ModelRegistry(base_dir=tmp_path)
    published_path = registry.publish_bundle(bundle, model_version="v_incomplete_manifest")

    # Tulis manifest yang kehilangan satu file wajib.
    manifest_file = published_path / "manifest.json"
    manifest_file.write_text('{"isolation_forest.joblib": "dummy"}', encoding="utf-8")

    with pytest.raises(ModelRegistryError, match="Manifest keys"):
        registry.load_bundle("v_incomplete_manifest")


def test_registry_no_active_version_without_explicit_or_env(tmp_path: Path, monkeypatch):
    """get_active_version() harus mengembalikan None bila versi eksplisit maupun env var tidak diset (tanpa fallback mtime)."""
    monkeypatch.delenv("RBTA_MODEL_VERSION", raising=False)
    metas = [make_meta(i) for i in range(1, 40)]
    bundle = train_reference_pipeline(metas, random_state=42, model_version="v_mtime_test")

    registry = ModelRegistry(base_dir=tmp_path)
    registry.publish_bundle(bundle, model_version="v_mtime_test")

    # Tanpa explicit_version atau env var, versi aktif HARUS None (tidak memilih direktori berdasarkan mtime).
    assert registry.get_active_version() is None


