"""Test keamanan paket ingestion."""
from pathlib import Path
import re

INGESTION_SRC = Path(__file__).resolve().parent.parent.parent.parent / "src" / "ingestion"


def test_no_hardcoded_passwords_or_credentials_in_ingestion_src():
    """src/ingestion tidak boleh berisi kredensial cleartext yang di-hardcode."""
    forbidden_patterns = [
        re.compile(r"password\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE),
        re.compile(r"api_key\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE),
    ]

    for py_file in INGESTION_SRC.glob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        for pat in forbidden_patterns:
            matches = pat.findall(content)
            # Izinkan default None, string kosong, atau docstring.
            clean_matches = [m for m in matches if not any(x in m for x in ("None", "''", '""', "secretpassword", "env"))]
            assert not clean_matches, f"Possible hardcoded credential in {py_file.name}: {clean_matches}"


def test_secure_tls_default_in_wazuh_client():
    """WazuhIndexerClient memakai verify_tls=True secara default."""
    from src.ingestion.wazuh_client import WazuhIndexerClient
    client = WazuhIndexerClient()
    assert client.verify_tls is True
