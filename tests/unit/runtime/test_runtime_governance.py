"""Test batas tanggung jawab paket runtime dan jaminan tanpa drop."""

from pathlib import Path

RUNTIME_SRC = Path(__file__).resolve().parent.parent.parent.parent / "src" / "runtime"


def test_shared_core_used_in_runtime():
    """Modul runtime tidak boleh menduplikasi logika RBTA atau ekstraksi fitur."""
    for py_file in RUNTIME_SRC.glob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        assert "class RBTAEngine" not in content  # harus import, bukan mendeklarasikan ulang
        assert "class SevenFeatureExtractor" not in content


def test_no_timestamp_drop_logic_in_runtime_src():
    """Kode produksi runtime tidak boleh membuang event berdasarkan timestamp."""
    forbidden_tokens = [
        "late_drop",
        "max_lateness",
        "drop_late",
        "too_old",
        "expired_alert",
    ]
    for py_file in RUNTIME_SRC.glob("*.py"):
        content = py_file.read_text(encoding="utf-8").lower()
        for token in forbidden_tokens:
            assert token not in content, f"Forbidden token '{token}' found in {py_file.name}"


def test_no_swallowed_canonicalization_exceptions_in_live_source():
    """Quarantine per hit: dokumen buruk dicatat ke last_bad_docs untuk dikarantina
    secara durable, tidak pernah dilewati diam-diam.
    """
    live_source_path = RUNTIME_SRC / "live_source.py"
    content = live_source_path.read_text(encoding="utf-8")
    assert "LiveCanonicalizationError" in content
    assert "last_bad_docs" in content
    assert "raise LiveCanonicalizationError" not in content
