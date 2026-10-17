"""Unit test SevenFeatureExtractor kanonis."""
import math
from datetime import datetime, timezone
import pytest
import pandas as pd

from src.contracts.meta_alert import MetaAlert
from src.features.extractor import (
    FEATURE_COLUMNS,
    FeatureExtractionError,
    SevenFeatureExtractor,
    compute_rule_diversity_shannon,
    compute_severity_dispersion,
)


def make_meta_alert(
    alert_count: int = 1,
    max_severity: int = 3,
    rule_id_distribution: dict[str, int] | None = None,
    severity_distribution: dict[int, int] | None = None,
    mitre_tactics: tuple[str, ...] = (),
    critical_mitre_present: bool = False,
    agent_criticality: int = 1,
) -> MetaAlert:
    """Helper untuk membuat MetaAlert valid bagi test ekstraksi fitur."""
    rule_dist = rule_id_distribution if rule_id_distribution is not None else {"5501": alert_count}
    sev_dist = severity_distribution if severity_distribution is not None else {max_severity: alert_count}

    return MetaAlert(
        meta_id=1,
        agent_id="001",
        agent_name="soc-1",
        rule_group_primary="pam",
        start_time=datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc),
        end_time=datetime(2026, 8, 28, 10, 5, 0, tzinfo=timezone.utc),
        alert_count=alert_count,
        max_severity=max_severity,
        rule_id_distribution=rule_dist,
        severity_distribution=sev_dist,
        mitre_tactics_unique=mitre_tactics,
        critical_mitre_present=critical_mitre_present,
        agent_criticality=agent_criticality,
        wazuh_alert_ids=("1",),
    )


def test_feature_columns_exact_order_and_names():
    """FEATURE_COLUMNS harus tepat 7 fitur sesuai urutan penelitian."""
    expected = (
        "max_severity",
        "mitre_tactic_count",
        "critical_mitre_tactic_present",
        "alert_count_log",
        "rule_diversity_shannon",
        "severity_dispersion",
        "agent_criticality",
    )
    assert FEATURE_COLUMNS == expected


def test_singleton_entropy_and_dispersion_are_zero():
    """Meta-alert singleton (alert_count=1) harus punya rule_diversity_shannon=0.0 dan severity_dispersion=0.0."""
    meta = make_meta_alert(alert_count=1, max_severity=5, rule_id_distribution={"5501": 1}, severity_distribution={5: 1})
    features = SevenFeatureExtractor.extract_features_dict(meta)

    assert features["rule_diversity_shannon"] == 0.0
    assert features["severity_dispersion"] == 0.0
    assert features["alert_count_log"] == math.log1p(1)
    assert features["max_severity"] == 5.0
    assert features["agent_criticality"] == 1.0


def test_repeated_same_rule_entropy_is_zero():
    """Meta-alert dengan banyak alert tetapi hanya 1 rule unik harus punya entropi ternormalisasi = 0.0."""
    meta = make_meta_alert(alert_count=100, rule_id_distribution={"5501": 100})
    entropy = compute_rule_diversity_shannon(meta.rule_id_distribution)
    assert entropy == 0.0


def test_balanced_two_rules_normalized_entropy_is_one():
    """Dua rule dengan proporsi sama (50%/50%) harus menghasilkan entropi Shannon ternormalisasi = 1.0."""
    rule_dist = {"rule_A": 50, "rule_B": 50}
    entropy = compute_rule_diversity_shannon(rule_dist)
    assert entropy == pytest.approx(1.0)


def test_unbalanced_multiple_rules_shannon_entropy():
    """Entropi Shannon untuk proporsi [0.5, 0.25, 0.25] dinormalisasi dengan ln(3)."""
    rule_dist = {"r1": 10, "r2": 5, "r3": 5}
    # H = -(0.5*ln(0.5) + 0.25*ln(0.25) + 0.25*ln(0.25)) = 0.5*0.693147 + 0.5*1.386294 = 1.03972
    # H_norm = 1.03972 / ln(3) = 1.03972 / 1.098612 = 0.94639
    expected_hnorm = -(0.5 * math.log(0.5) + 2 * (0.25 * math.log(0.25))) / math.log(3)
    entropy = compute_rule_diversity_shannon(rule_dist)
    assert entropy == pytest.approx(expected_hnorm)


def test_severity_dispersion_calculation():
    """Severity dispersion adalah simpangan baku populasi dari rule level."""
    # 5 alert level 3 dan 5 alert level 7 -> mean = 5.0, std = 2.0
    sev_dist = {3: 5, 7: 5}
    dispersion = compute_severity_dispersion(sev_dist)
    assert dispersion == pytest.approx(2.0)

    # Severity identik -> dispersion = 0.0
    assert compute_severity_dispersion({4: 20}) == 0.0


def test_mitre_tactics_count_and_critical_flag():
    """Taktik MITRE dihitung unik dan flag kritis direpresentasikan sebagai 1.0 / 0.0."""
    meta1 = make_meta_alert(
        mitre_tactics=("Execution", "Initial Access", "Defense Evasion"),
        critical_mitre_present=True,
    )
    features1 = SevenFeatureExtractor.extract_features_dict(meta1)
    assert features1["mitre_tactic_count"] == 3.0
    assert features1["critical_mitre_tactic_present"] == 1.0

    meta2 = make_meta_alert(
        mitre_tactics=(),
        critical_mitre_present=False,
    )
    features2 = SevenFeatureExtractor.extract_features_dict(meta2)
    assert features2["mitre_tactic_count"] == 0.0
    assert features2["critical_mitre_tactic_present"] == 0.0


def test_alert_count_log_is_log1p():
    """alert_count_log harus sama dengan math.log1p(alert_count)."""
    meta = make_meta_alert(alert_count=42)
    features = SevenFeatureExtractor.extract_features_dict(meta)
    assert features["alert_count_log"] == pytest.approx(math.log1p(42))


def test_agent_criticality_float_conversion():
    """agent_criticality diekstrak sebagai float dalam rentang domain [1.0, 4.0]."""
    meta = make_meta_alert(agent_criticality=4)
    features = SevenFeatureExtractor.extract_features_dict(meta)
    assert features["agent_criticality"] == 4.0


def test_extract_features_vector_exact_order():
    """extract_features_vector mengembalikan tuple float sesuai urutan FEATURE_COLUMNS."""
    meta = make_meta_alert(
        alert_count=10,
        max_severity=8,
        mitre_tactics=("Impact",),
        critical_mitre_present=True,
        agent_criticality=3,
        rule_id_distribution={"5501": 5, "5502": 5},
        severity_distribution={6: 5, 8: 5},
    )
    vec = SevenFeatureExtractor.extract_features_vector(meta)
    assert isinstance(vec, tuple)
    assert len(vec) == 7

    # Cek urutan.
    assert vec[0] == 8.0  # max_severity
    assert vec[1] == 1.0  # mitre_tactic_count
    assert vec[2] == 1.0  # critical_mitre_tactic_present
    assert vec[3] == pytest.approx(math.log1p(10))  # alert_count_log
    assert vec[4] == pytest.approx(1.0)  # rule_diversity_shannon (2 rule seimbang)
    assert vec[5] == pytest.approx(1.0)  # severity_dispersion (6 dan 8, mean 7, std 1)
    assert vec[6] == 3.0  # agent_criticality


def test_extract_features_df_schema_and_dtypes():
    """extract_features_df mengembalikan pd.DataFrame dengan FEATURE_COLUMNS persis dan dtype float64."""
    meta1 = make_meta_alert(alert_count=5, max_severity=4)
    meta2 = make_meta_alert(alert_count=20, max_severity=12)

    df = SevenFeatureExtractor.extract_features_df([meta1, meta2])
    assert isinstance(df, pd.DataFrame)
    assert list(df.columns) == list(FEATURE_COLUMNS)
    assert len(df) == 2
    assert all(df.dtypes == "float64")


def test_missing_required_aggregate_raises_error():
    """Objek input yang tidak punya atribut MetaAlert wajib harus melempar FeatureExtractionError tanpa fallback diam-diam."""
    class FakeMeta:
        pass

    with pytest.raises(FeatureExtractionError, match="Missing or invalid MetaAlert"):
        SevenFeatureExtractor.extract_features_dict(FakeMeta())
