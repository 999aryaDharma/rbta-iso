"""T5: override kekritisan agen via RBTA_AGENT_CRITICALITY_FILE; tanpa env perilaku 100% sama."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from src.config import domain
from src.config.domain import load_agent_criticality_file

REPO = Path(__file__).resolve().parents[3]
BUILTIN = {
    "soc-1": 1, "pusatkarir": 3, "dfir-iris": 4, "siput": 2, "proxy-manager": 3,
    "e-kuesioner": 2, "sads": 3, "dvwa": 1, "wazuh-soc": 1,
}
# compute_derivation_hash() dengan tabel bawaan (sama dengan commit 16ab574).
BUILTIN_DERIVATION_HASH = "0586ed4dc65177a10bdf25e9435f8b4be340a6165157d95acab8c96e3255701a"


def test_without_env_tables_are_untouched():
    assert os.environ.get("RBTA_AGENT_CRITICALITY_FILE") is None
    assert domain.AGENT_CRITICALITY_OVERRIDE is None
    assert domain.AGENT_CRITICALITY == BUILTIN
    from src.runtime.durable_state import compute_derivation_hash

    assert compute_derivation_hash() == BUILTIN_DERIVATION_HASH
    assert domain.get_agent_criticality("agent-test") == 1


def test_loader_normalizes_and_hashes(tmp_path: Path):
    f = tmp_path / "crit.json"
    f.write_text(json.dumps({" Elsa ": 3, "007": 4}), encoding="utf-8")
    mapping, sha = load_agent_criticality_file(f)
    assert mapping == {"elsa": 3, "007": 4}
    assert len(sha) == 64


@pytest.mark.parametrize("content", ['{"x": 5}', '{"x": 0}', '{"x": true}', '{"x": "3"}', '["x"]', "{bad", '{"": 2}'])
def test_loader_rejects_invalid_files(tmp_path: Path, content: str):
    f = tmp_path / "crit.json"
    f.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match="RBTA_AGENT_CRITICALITY_FILE"):
        load_agent_criticality_file(f)


def test_env_file_overrides_on_top_of_builtin(tmp_path: Path):
    f = tmp_path / "crit.json"
    f.write_text(json.dumps({"elsa": 2, "dfir-iris": 3}), encoding="utf-8")
    code = (
        "import json; from src.config import domain as d; "
        "print(json.dumps([d.get_agent_criticality('ELSA'), d.get_agent_criticality('dfir-iris'), "
        "d.get_agent_criticality('pusatkarir'), d.AGENT_CRITICALITY_OVERRIDE['entries'], "
        "d.AGENT_CRITICALITY_OVERRIDE['sha256']]))"
    )
    env = {**os.environ, "RBTA_AGENT_CRITICALITY_FILE": str(f)}
    out = subprocess.run([sys.executable, "-c", code], cwd=REPO, env=env, capture_output=True, text=True, check=True)
    elsa, dfir, pusat, entries, sha = json.loads(out.stdout)
    assert (elsa, dfir, pusat, entries) == (2, 3, 3, 2)
    assert sha == load_agent_criticality_file(f)[1]


def test_invalid_env_file_fails_closed(tmp_path: Path):
    f = tmp_path / "crit.json"
    f.write_text('{"elsa": 9}', encoding="utf-8")
    env = {**os.environ, "RBTA_AGENT_CRITICALITY_FILE": str(f)}
    out = subprocess.run([sys.executable, "-c", "import src.config.domain"], cwd=REPO, env=env, capture_output=True, text=True)
    assert out.returncode != 0
    assert "must map a non-empty agent to an integer 1-4" in out.stderr
