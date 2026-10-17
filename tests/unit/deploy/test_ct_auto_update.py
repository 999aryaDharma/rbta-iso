"""T13: deploy/ct/auto-update.sh hanya men-deploy commit origin yang bertag release-*."""

import os
from pathlib import Path
import shutil
import subprocess

import pytest

SCRIPT = Path(__file__).resolve().parents[3] / "deploy" / "ct" / "auto-update.sh"
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(
    BASH is None or "system32" in BASH.lower(), reason="butuh bash POSIX (Git Bash/Linux), bukan WSL launcher"
)


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture()
def env(tmp_path: Path):
    origin = tmp_path / "origin.git"
    _git(tmp_path, "init", "-q", "--bare", "-b", "main", str(origin))
    work = tmp_path / "work"
    _git(tmp_path, "clone", "-q", str(origin), str(work))
    for repo in (work,):
        _git(repo, "config", "user.email", "t@example.invalid")
        _git(repo, "config", "user.name", "t")
    (work / "deploy" / "ct").mkdir(parents=True)
    (work / "deploy" / "ct" / "README").write_text("v1\n")
    _git(work, "add", ".")
    _git(work, "commit", "-q", "-m", "v1")
    _git(work, "push", "-q", "origin", "main")
    ct = tmp_path / "ct"
    _git(tmp_path, "clone", "-q", str(origin), str(ct))
    (ct / ".git" / "info" / "exclude").write_text(".cd.lock\n.cd.last-untagged\ncd.log\n")

    stubs = tmp_path / "bin"
    stubs.mkdir()
    calls = tmp_path / "calls.log"
    for name, body in (("docker", f'echo docker "$@" >> "{calls.as_posix()}"'), ("curl", "exit 0"), ("flock", "exit 0")):
        stub = stubs / name
        stub.write_text(f"#!/usr/bin/env bash\n{body}\n", newline="\n")
        stub.chmod(0o755)
    run_env = {**os.environ, "PATH": f"{stubs}{os.pathsep}{os.environ['PATH']}", "RBTA_REPO_DIR": str(ct),
               "RBTA_CD_BRANCH": "main", "RBTA_CD_LOG": str(tmp_path / "cd.log")}
    return work, ct, calls, run_env, tmp_path / "cd.log"


def _commit(work: Path, text: str, tag: str = "") -> str:
    (work / "deploy" / "ct" / "README").write_text(text + "\n")
    _git(work, "commit", "-q", "-am", text)
    if tag:
        _git(work, "tag", tag)
    _git(work, "push", "-q", "--tags", "origin", "main")
    return _git(work, "rev-parse", "HEAD")


def _run(run_env) -> None:
    subprocess.run([BASH, SCRIPT.as_posix()], env=run_env, check=True, capture_output=True, text=True)


def test_untagged_commit_is_ignored_and_tagged_commit_deploys(env):
    work, ct, calls, run_env, log = env
    before = _git(ct, "rev-parse", "HEAD")

    _commit(work, "v2")
    _run(run_env)
    _run(run_env)
    assert _git(ct, "rev-parse", "HEAD") == before
    assert not calls.exists()
    assert log.read_text().count("SKIP") == 1  # sekali per SHA

    tagged = _commit(work, "v3", tag="release-2026.10.17")
    _run(run_env)
    assert _git(ct, "rev-parse", "HEAD") == tagged
    assert "docker compose build" in calls.read_text()
    assert "release-2026.10.17" in log.read_text()


def test_non_release_tag_does_not_deploy(env):
    work, ct, calls, run_env, _ = env
    before = _git(ct, "rev-parse", "HEAD")
    _commit(work, "v2", tag="v2-candidate")
    _run(run_env)
    assert _git(ct, "rev-parse", "HEAD") == before and not calls.exists()
