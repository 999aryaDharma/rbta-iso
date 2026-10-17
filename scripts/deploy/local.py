#!/usr/bin/env python3
"""Launcher Docker Desktop lintas platform untuk demo RBTA lokal."""

import argparse
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import subprocess
import sys
import time
from typing import Dict, List, Optional, Sequence
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.deploy.read_env import parse_env_file


SUPPORTED_REPLAY_SUFFIXES = (".jsonl", ".jsonl.gz")
LOCAL_DEPLOY_DIR = REPO_ROOT / "deploy" / "local"


class LocalConfigurationError(RuntimeError):
    """Dilempar sebelum Docker dijalankan bila konfigurasi lokal tidak aman atau tidak lengkap."""


def normalize_docker_host_path(value: str, platform: Optional[str] = None) -> str:
    """Normalisasi path host untuk Compose tanpa merusak huruf drive Windows."""
    active_platform = platform or sys.platform
    expanded = os.path.expandvars(value.strip())
    if active_platform.startswith("win"):
        return PureWindowsPath(expanded).as_posix()
    if os.name == "nt":
        # Host Windows mensimulasikan platform POSIX: resolve() akan menempelkan huruf drive.
        return PurePosixPath(os.path.expanduser(expanded)).as_posix()
    return str(Path(expanded).expanduser().resolve())


def discover_replay_files(directory: Path) -> List[Path]:
    """Cari input alert saja; sidecar `.meta` sengaja tidak diikutkan."""
    if not directory.is_dir():
        raise LocalConfigurationError(f"Replay directory does not exist: {directory}")
    return sorted(
        (item for item in directory.iterdir() if item.is_file() and item.name.endswith(SUPPORTED_REPLAY_SUFFIXES)),
        key=lambda item: item.name,
    )


def validate_local_configuration(config: Dict[str, str], platform: Optional[str] = None) -> Dict[str, str]:
    """Validasi dan normalisasi seluruh kontrak runtime lokal."""
    required = ("RBTA_API_KEY", "RBTA_MODEL_VERSION", "RBTA_HOST_PORT", "RBTA_REPLAY_HOST_DIR", "RBTA_MODEL_HOST_DIR")
    missing = [key for key in required if not config.get(key, "").strip()]
    if missing:
        raise LocalConfigurationError(f"Missing required configuration: {', '.join(missing)}")
    try:
        port = int(config["RBTA_HOST_PORT"])
    except ValueError as exc:
        raise LocalConfigurationError("RBTA_HOST_PORT must be an integer between 1024 and 65535") from exc
    if not 1024 <= port <= 65535:
        raise LocalConfigurationError("RBTA_HOST_PORT must be an integer between 1024 and 65535")

    active_platform = platform or sys.platform

    def resolve_config_path(value: str) -> str:
        if active_platform.startswith("win"):
            candidate = PureWindowsPath(value)
            if candidate.is_absolute():
                return candidate.as_posix()
        else:
            candidate = Path(value).expanduser()
            if candidate.is_absolute():
                return str(candidate.resolve())
        return normalize_docker_host_path(str(REPO_ROOT / value), active_platform)

    normalized = dict(config)
    normalized["RBTA_REPLAY_HOST_DIR"] = resolve_config_path(config["RBTA_REPLAY_HOST_DIR"])
    normalized["RBTA_MODEL_HOST_DIR"] = resolve_config_path(config["RBTA_MODEL_HOST_DIR"])
    replay_path = Path(normalized["RBTA_REPLAY_HOST_DIR"])
    model_path = Path(normalized["RBTA_MODEL_HOST_DIR"]) / config["RBTA_MODEL_VERSION"]
    files = discover_replay_files(replay_path)
    if not files:
        raise LocalConfigurationError(
            f"Replay directory '{replay_path}' contains no .jsonl or .jsonl.gz datasets"
        )
    if not model_path.is_dir():
        raise LocalConfigurationError(f"Model version directory does not exist: {model_path}")
    normalized["RBTA_REPLAY_FILE_COUNT"] = str(len(files))
    return normalized


def _compose_command(env_file: Path, action: Sequence[str]) -> List[str]:
    return [
        "docker", "compose", "--env-file", str(env_file),
        "-f", str(LOCAL_DEPLOY_DIR / "compose.yml"), *action,
    ]


def _request_json(url: str, api_key: str, method: str = "GET") -> Dict[str, object]:
    request = Request(url, method=method, headers={"Authorization": f"Bearer {api_key}"})
    with urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def _wait_ready(base_url: str, timeout_seconds: int = 120) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error = "service has not responded"
    while time.monotonic() < deadline:
        try:
            with urlopen(f"{base_url}/ready", timeout=3) as response:
                if response.status == 200:
                    return
        except (HTTPError, URLError, TimeoutError) as exc:
            last_error = str(exc)
        time.sleep(1)
    raise RuntimeError(f"RBTA service did not become ready within {timeout_seconds}s: {last_error}")


def _index_catalog(base_url: str, api_key: str) -> None:
    status = _request_json(f"{base_url}/api/v1/replay/datasets/refresh", api_key, method="POST")
    while status.get("status") in {"RUNNING", "STARTING"}:
        completed = status.get("completed_files", 0)
        total = status.get("total_files", 0)
        current = status.get("current_file") or "menyiapkan"
        print(f"[index] {completed}/{total} — {current}", flush=True)
        time.sleep(1)
        status = _request_json(f"{base_url}/api/v1/replay/datasets/catalog-status", api_key)
    if status.get("status") != "COMPLETED":
        raise RuntimeError(f"Dataset indexing failed: {status.get('last_error') or status}")
    if int(status.get("invalid_files", 0)) > 0:
        raise RuntimeError(
            f"Dataset indexing found {status['invalid_files']} invalid file(s); inspect the Demo page before replay"
        )
    print(f"[index] selesai: {status.get('completed_files', 0)} dataset siap")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="RBTA hybrid local launcher for Docker Desktop/WSL")
    parser.add_argument("command", choices=("up", "down", "status", "logs", "index"))
    parser.add_argument("--env-file", type=Path, default=LOCAL_DEPLOY_DIR / ".env")
    parser.add_argument("--skip-index", action="store_true", help="Return after startup without catalog indexing")
    args = parser.parse_args(argv)

    try:
        config = validate_local_configuration(parse_env_file(args.env_file))
        compose_env = os.environ.copy()
        compose_env.update(config)
        subprocess.run(["docker", "compose", "version"], check=True, capture_output=True)
        base_url = f"http://127.0.0.1:{config['RBTA_HOST_PORT']}"

        if args.command == "up":
            subprocess.run(_compose_command(args.env_file, ("up", "-d", "--build")), check=True, env=compose_env)
            _wait_ready(base_url)
            if not args.skip_index:
                _index_catalog(base_url, config["RBTA_API_KEY"])
            print(f"Demo siap: {base_url}/dashboard/demo")
        elif args.command == "index":
            _wait_ready(base_url)
            _index_catalog(base_url, config["RBTA_API_KEY"])
        elif args.command == "down":
            subprocess.run(_compose_command(args.env_file, ("down",)), check=True, env=compose_env)
        elif args.command == "status":
            subprocess.run(_compose_command(args.env_file, ("ps",)), check=True, env=compose_env)
        else:
            subprocess.run(_compose_command(args.env_file, ("logs", "-f", "--tail", "200")), check=True, env=compose_env)
        return 0
    except (FileNotFoundError, LocalConfigurationError, RuntimeError, subprocess.CalledProcessError, HTTPError, URLError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
