#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# RBTA + Isolation Forest — ASUS Production Deployment Preflight Validator
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DEPLOY_DIR="${ROOT_DIR}/deploy/asus"

ENV_FILE="${RBTA_ENV_FILE:-${DEPLOY_DIR}/.env}"

echo "=== [1/6] Resolving Environment Configuration ==="
if [ ! -f "${ENV_FILE}" ]; then
  echo "ERROR: Environment configuration file not found at: ${ENV_FILE}" >&2
  echo "       Please create it by copying the template:" >&2
  echo "       cp ${DEPLOY_DIR}/.env.example ${ENV_FILE}" >&2
  exit 1
fi
echo "Environment file resolved: ${ENV_FILE}"

get_env() {
  python3 "${SCRIPT_DIR}/read_env.py" "${ENV_FILE}" "$1" --default "${2:-}"
}
require_env() {
  python3 "${SCRIPT_DIR}/read_env.py" "${ENV_FILE}" "$1" --require
}

echo "=== [2/6] Validating Mandatory Fail-Closed Variables ==="
RBTA_API_KEY=$(require_env "RBTA_API_KEY")
echo "✓ RBTA_API_KEY: configured (non-empty)"

RBTA_MODEL_VERSION=$(require_env "RBTA_MODEL_VERSION")
echo "✓ RBTA_MODEL_VERSION: ${RBTA_MODEL_VERSION}"

echo "=== [3/6] Validating Host Port Configuration & Collision ==="
RBTA_HOST_PORT=$(require_env "RBTA_HOST_PORT")

if ! [[ "${RBTA_HOST_PORT}" =~ ^[0-9]+$ ]] || [ "${RBTA_HOST_PORT}" -lt 1024 ] || [ "${RBTA_HOST_PORT}" -gt 65535 ]; then
  echo "ERROR: RBTA_HOST_PORT must be an integer between 1024 and 65535, got '${RBTA_HOST_PORT}'." >&2
  exit 1
fi
echo "✓ RBTA_HOST_PORT: ${RBTA_HOST_PORT} (valid range)"

# Check if port is already bound
PORT_IN_USE=false
if command -v ss >/dev/null 2>&1; then
  if ss -tulpn 2>/dev/null | grep -qE "(:${RBTA_HOST_PORT}[[:space:]]|:${RBTA_HOST_PORT}$)"; then
    PORT_IN_USE=true
  fi
elif command -v netstat >/dev/null 2>&1; then
  if netstat -tuln 2>/dev/null | grep -qE "(:${RBTA_HOST_PORT}[[:space:]]|:${RBTA_HOST_PORT}$)"; then
    PORT_IN_USE=true
  fi
fi

if [ "${PORT_IN_USE}" = "true" ]; then
  # Check if the existing listener is our own RBTA deployment container
  OUR_CONTAINER=false
  if command -v docker >/dev/null 2>&1; then
    CONTAINER_ID=$(docker ps -q --filter "publish=${RBTA_HOST_PORT}" 2>/dev/null || true)
    if [ -n "${CONTAINER_ID}" ]; then
      CONTAINER_NAME=$(docker inspect --format '{{.Name}}' "${CONTAINER_ID}" 2>/dev/null || true)
      if [[ "${CONTAINER_NAME}" == *"rbta"* ]]; then
        OUR_CONTAINER=true
        echo "Notice: Port ${RBTA_HOST_PORT} is currently bound by existing container ${CONTAINER_NAME} (redeploy permitted)."
      fi
    fi
  fi

  if [ "${OUR_CONTAINER}" != "true" ]; then
    echo "ERROR: Port ${RBTA_HOST_PORT} is already in use by an unrelated process/container. Cannot bind fail-closed." >&2
    if command -v ss >/dev/null 2>&1; then
      echo "Active listener details:" >&2
      ss -tulpn | grep -E "(:${RBTA_HOST_PORT}[[:space:]]|:${RBTA_HOST_PORT}$)" >&2 || true
    fi
    exit 1
  fi
fi
echo "✓ Host Port Check: Available / Redeploy Safe"

echo "=== [4/6] Validating Host Directory Paths & Replay-Only Readiness ==="
STATE_DIR=$(get_env "RBTA_STATE_HOST_DIR" "${ROOT_DIR}/state")
MODELS_DIR=$(get_env "RBTA_MODEL_HOST_DIR" "${ROOT_DIR}/models")
REPLAY_DIR=$(get_env "RBTA_REPLAY_HOST_DIR" "${ROOT_DIR}/data/replay")

mkdir -p "${STATE_DIR}"
echo "✓ State directory: ${STATE_DIR}"

if [ ! -d "${MODELS_DIR}/${RBTA_MODEL_VERSION}" ]; then
  echo "ERROR: Model directory '${MODELS_DIR}/${RBTA_MODEL_VERSION}' does not exist." >&2
  exit 1
fi
echo "✓ Model registry directory: ${MODELS_DIR}/${RBTA_MODEL_VERSION}"

if [ ! -d "${REPLAY_DIR}" ]; then
  echo "ERROR: Replay directory '${REPLAY_DIR}' does not exist." >&2
  exit 1
fi

# Require at least one ready *.jsonl or *.jsonl.gz dataset.
# `.meta` sidecars and unrelated archives are intentionally excluded.
mapfile -d '' READY_FILES < <(find "${REPLAY_DIR}" -maxdepth 1 -type f \( -name '*.jsonl' -o -name '*.jsonl.gz' \) -print0 2>/dev/null || true)
JSONL_COUNT=${#READY_FILES[@]}
mapfile -d '' UNSUPPORTED_COMPRESSED_FILES < <(find "${REPLAY_DIR}" -maxdepth 1 -type f \( \( -name '*.gz' ! -name '*.jsonl.gz' \) -o -name '*.part' \) -print0 2>/dev/null || true)
COMPRESSED_COUNT=${#UNSUPPORTED_COMPRESSED_FILES[@]}

if [ "${JSONL_COUNT}" -eq 0 ]; then
  if [ "${COMPRESSED_COUNT}" -gt 0 ]; then
    echo "ERROR: Replay directory '${REPLAY_DIR}' contains only unsupported archive parts." >&2
    echo "       Ready formats are *.jsonl and *.jsonl.gz." >&2
    exit 1
  else
    echo "ERROR: Replay directory '${REPLAY_DIR}' contains zero *.jsonl or *.jsonl.gz datasets." >&2
    exit 1
  fi
fi

# Ensure at least one dataset is non-empty
NON_EMPTY_JSONL=false
for f in "${READY_FILES[@]}"; do
  if [ -s "$f" ]; then
    NON_EMPTY_JSONL=true
    break
  fi
done

if [ "${NON_EMPTY_JSONL}" != "true" ]; then
  echo "ERROR: All supported replay datasets in '${REPLAY_DIR}' are empty." >&2
  exit 1
fi
echo "✓ Replay archive readiness: ${JSONL_COUNT} .jsonl/.jsonl.gz dataset(s) found (non-empty)"

echo "=== [5/6] Validating Container Engine & Compose Specification ==="
command -v docker >/dev/null 2>&1 || { echo "ERROR: docker command not found." >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "ERROR: docker compose not available." >&2; exit 1; }

docker compose --env-file "${ENV_FILE}" -f "${DEPLOY_DIR}/compose.yml" config --quiet
echo "✓ Docker Compose manifest: VALID"

echo "=== [6/6] Checking Source Mode Invariant ==="
SOURCE_MODE=$(get_env "RBTA_SOURCE_MODE" "DEFERRED")
if [ "${SOURCE_MODE}" != "DEFERRED" ] && [ "${SOURCE_MODE}" != "LIVE" ]; then
  echo "ERROR: RBTA_SOURCE_MODE must be 'DEFERRED' or 'LIVE', got '${SOURCE_MODE}'." >&2
  exit 1
fi
echo "✓ Source mode: ${SOURCE_MODE}"

echo ""
echo ">>> PREFLIGHT CHECK COMPLETED: ALL DEPLOYMENT PREREQUISITES SATISFIED <<<"
