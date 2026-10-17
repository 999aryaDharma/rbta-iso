"""Script validasi bundle artefak model produksi memakai ModelRegistry."""

import argparse
from pathlib import Path
import sys

# Pastikan root repository ada di sys.path.
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.model.registry import ModelRegistry, ModelRegistryError


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate model artifact bundle integrity.")
    parser.add_argument("--models-dir", required=True, type=Path, help="Path to models directory.")
    parser.add_argument("--version", required=True, type=str, help="Model version to validate.")
    args = parser.parse_args()

    models_dir = args.models_dir.resolve()
    version = args.version.strip()

    if not version:
        print("ERROR: Model version cannot be empty.", file=sys.stderr)
        return 1

    if not models_dir.exists():
        print(f"ERROR: Models directory '{models_dir}' does not exist.", file=sys.stderr)
        return 1

    try:
        registry = ModelRegistry(base_dir=models_dir, explicit_version=version)
        bundle = registry.load_bundle(version)
        print(f"PASS: Successfully validated model bundle '{version}' in '{models_dir}'.")
        print(f"      Manifest verified with sha256 checksums on all 6 artifacts.")
        return 0
    except ModelRegistryError as exc:
        print(f"FAIL: Model registry integrity check failed: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"FAIL: Unexpected error validating model '{version}': {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
