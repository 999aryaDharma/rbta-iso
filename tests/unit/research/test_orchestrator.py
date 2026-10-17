"""Test orkestrator penelitian kanonis (urutan fase, propagasi delta-t, subset, mode input)."""

from pathlib import Path
import json
import pytest
from unittest.mock import patch, MagicMock

from src.research.orchestrator import (
    run_canonical_research_pipeline,
    ResearchInputError,
    _generate_engineering_smoke_fixture,
    main,
)


def test_missing_input_never_falls_back_to_fixture():
    """File input yang tidak ada melempar ResearchInputError / FileNotFoundError dan langsung gagal."""
    with pytest.raises((ResearchInputError, FileNotFoundError)):
        run_canonical_research_pipeline(raw_file_path=Path("non_existent_file_12345.jsonl"))


def test_fixture_mode_explicitly_marked_non_research(tmp_path):
    """Mode fixture mengisi research_results_valid_for_seminar=False di metadata."""
    fixture_alerts = _generate_engineering_smoke_fixture(n_alerts=50, seed=42)
    summary = run_canonical_research_pipeline(
        raw_alerts=fixture_alerts,
        output_base_dir=tmp_path,
        is_fixture_mode=True,
        random_seed=42,
    )
    manifest = summary["manifest"]
    assert manifest["input_mode"] == "engineering_fixture"
    assert manifest["research_results_valid_for_seminar"] is False


def test_auto_delta_selection_drives_final_rbta(tmp_path):
    """Di mode auto, delta-t elbow yang direkomendasikan dipakai untuk RBTA final."""
    fixture_alerts = _generate_engineering_smoke_fixture(n_alerts=60, seed=42)
    summary = run_canonical_research_pipeline(
        raw_alerts=fixture_alerts,
        output_base_dir=tmp_path,
        is_fixture_mode=True,
        delta_t_mode="auto",
        random_seed=42,
    )
    manifest = summary["manifest"]
    assert manifest["delta_t_selection_source"] == "sensitivity_elbow"
    assert manifest["selected_delta_t_minutes"] == manifest["recommended_delta_t_minutes"]
    assert manifest["selected_delta_t_minutes"] > 0


def test_manual_delta_override_is_explicit(tmp_path):
    """Override delta manual dicatat eksplisit dan dipakai untuk RBTA final."""
    fixture_alerts = _generate_engineering_smoke_fixture(n_alerts=60, seed=42)
    summary = run_canonical_research_pipeline(
        raw_alerts=fixture_alerts,
        output_base_dir=tmp_path,
        is_fixture_mode=True,
        delta_t_mode=30,
        random_seed=42,
    )
    manifest = summary["manifest"]
    assert manifest["delta_t_selection_source"] == "manual_override"
    assert manifest["selected_delta_t_minutes"] == 30
    assert "recommended_delta_t_minutes" in manifest


def test_runtime_uses_exactly_eight_subsets(tmp_path):
    """Orkestrator menjalankan bukti kompleksitas runtime dengan tepat 8 subset."""
    fixture_alerts = _generate_engineering_smoke_fixture(n_alerts=60, seed=42)
    summary = run_canonical_research_pipeline(
        raw_alerts=fixture_alerts,
        output_base_dir=tmp_path,
        is_fixture_mode=True,
        random_seed=42,
    )
    phase_a = summary["phase_a"]
    assert len(phase_a["complexity_subsets"]) == 8


def test_official_pipeline_records_chronological_reference_calibration_test_split(tmp_path):
    fixture_alerts = _generate_engineering_smoke_fixture(n_alerts=120, seed=42)
    summary = run_canonical_research_pipeline(
        raw_alerts=fixture_alerts,
        output_base_dir=tmp_path,
        is_fixture_mode=True,
        random_seed=42,
    )

    split = summary["manifest"]["temporal_split"]
    assert split["strategy"] == "chronological"
    assert split["reference"]["n_raw"] == 72
    assert split["calibration"]["n_raw"] == 24
    assert split["test"]["n_raw"] == 24
    assert sum(part["n_raw"] for key, part in split.items() if key != "strategy") == 120
    assert summary["phase_b"]["evaluation_population"] == "test_without_refit"


def test_directory_input_records_multi_file_corpus_provenance(tmp_path):
    corpus_dir = tmp_path / "indexer-export"
    corpus_dir.mkdir()
    fixture_alerts = _generate_engineering_smoke_fixture(n_alerts=60, seed=42)
    for filename, subset in (("2026.04.02.jsonl", fixture_alerts[:30]), ("2026.04.03.jsonl", fixture_alerts[30:])):
        rows = []
        for alert in subset:
            rows.append({
                "id": alert.wazuh_alert_id,
                "timestamp": alert.timestamp.isoformat(),
                "agent": {"id": alert.agent_id, "name": alert.agent_name},
                "rule": {
                    "id": alert.rule_id,
                    "level": alert.rule_level,
                    "groups": [alert.rule_group_primary],
                    "mitre": {"tactic": list(alert.mitre_tactics)},
                },
            })
        (corpus_dir / filename).write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    (corpus_dir / "2026.04.02.meta").write_text("{}", encoding="utf-8")

    summary = run_canonical_research_pipeline(
        raw_file_path=corpus_dir,
        output_base_dir=tmp_path / "runs",
        model_version="directory-input-v1",
        random_seed=42,
        git_commit="a" * 40,
    )

    corpus = summary["manifest"]["input_corpus"]
    assert corpus["source_kind"] == "directory"
    assert corpus["file_count"] == 2
    assert corpus["event_count"] == 60
    assert [item["name"] for item in corpus["files"]] == ["2026.04.02.jsonl", "2026.04.03.jsonl"]
    assert summary["manifest"]["research_results_valid_for_seminar"] is True


def test_canonical_research_phase_order(tmp_path):
    """Fase penelitian dieksekusi dengan urutan yang ketat."""
    call_order = []

    fixture_alerts = _generate_engineering_smoke_fixture(n_alerts=60, seed=42)

    import src.research.orchestrator as orch

    orig_sens = orch.run_delta_t_sensitivity_analysis
    def spy_sens(*args, **kwargs):
        call_order.append("sensitivity")
        return orig_sens(*args, **kwargs)

    orig_batch_runner = orch.BatchResearchRunner
    def spy_batch_runner(*args, **kwargs):
        call_order.append(f"batch_runner_init_delta_{kwargs.get('base_delta_t')}_adaptive_{kwargs.get('adaptive')}")
        instance = orig_batch_runner(*args, **kwargs)
        orig_run = instance.run
        def spy_run(*r_args, **r_kwargs):
            call_order.append("final_rbta_run")
            return orig_run(*r_args, **r_kwargs)
        instance.run = spy_run
        return instance

    orig_fixed = orch.run_fixed_window_baseline
    def spy_fixed(*args, **kwargs):
        call_order.append("fixed_window")
        return orig_fixed(*args, **kwargs)

    orig_noise = orch.run_noise_robustness_evaluation
    def spy_noise(*args, **kwargs):
        call_order.append("noise")
        return orig_noise(*args, **kwargs)

    orig_runtime = orch.run_runtime_complexity_evaluation
    def spy_runtime(*args, **kwargs):
        call_order.append("runtime")
        return orig_runtime(*args, **kwargs)

    orig_extractor = orch.SevenFeatureExtractor.extract_features_df
    def spy_extractor(*args, **kwargs):
        call_order.append("seven_features")
        return orig_extractor(*args, **kwargs)

    orig_train = orch.train_reference_pipeline
    def spy_train(*args, **kwargs):
        call_order.append("train_model")
        return orig_train(*args, **kwargs)

    orig_scoring_cls = orch.ScoringPipeline
    def spy_scoring_pipeline(*args, **kwargs):
        instance = orig_scoring_cls(*args, **kwargs)
        orig_score_m = instance.score_meta_alerts
        def spy_score_m(metas, *m_args, **m_kwargs):
            call_order.append("scoring")
            return orig_score_m(metas, *m_args, **m_kwargs)
        instance.score_meta_alerts = spy_score_m
        return instance

    orig_silhouette = orch.run_structural_silhouette_evaluation
    def spy_silhouette(*args, **kwargs):
        call_order.append("structural_silhouette")
        return orig_silhouette(*args, **kwargs)

    with patch.object(orch, "run_delta_t_sensitivity_analysis", side_effect=spy_sens), \
         patch.object(orch, "BatchResearchRunner", side_effect=spy_batch_runner), \
         patch.object(orch, "run_fixed_window_baseline", side_effect=spy_fixed), \
         patch.object(orch, "run_noise_robustness_evaluation", side_effect=spy_noise), \
         patch.object(orch, "run_runtime_complexity_evaluation", side_effect=spy_runtime), \
         patch.object(orch.SevenFeatureExtractor, "extract_features_df", side_effect=spy_extractor), \
         patch.object(orch, "train_reference_pipeline", side_effect=spy_train), \
         patch.object(orch, "ScoringPipeline", side_effect=spy_scoring_pipeline), \
         patch.object(orch, "run_structural_silhouette_evaluation", side_effect=spy_silhouette):

        summary = orch.run_canonical_research_pipeline(
            raw_alerts=fixture_alerts,
            output_base_dir=tmp_path,
            is_fixture_mode=True,
            delta_t_mode="auto",
            random_seed=42,
        )

    expected_phases = [
        "sensitivity",
        "final_rbta_run",
        "final_rbta_run",
        "final_rbta_run",
        "fixed_window",
        "noise",
        "runtime",
        "train_model",
        "scoring",
        "structural_silhouette",
    ]

    filtered_calls = [c for c in call_order if c in expected_phases]
    assert filtered_calls == expected_phases

    # RBTA final memakai adaptive == True.
    init_call = [c for c in call_order if c.startswith("batch_runner_init")][0]
    assert "adaptive_True" in init_call
