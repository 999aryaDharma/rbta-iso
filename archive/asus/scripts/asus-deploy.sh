#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# RBTA + Isolation Forest — ASUS Production Deployment Script
# ==============================================================================

VERIFY_ONLY=false
for arg in "$@"; do
  if [ "$arg" = "--verify-only" ]; then
    VERIFY_ONLY=true
  fi
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DEPLOY_DIR="${ROOT_DIR}/deploy/asus"
ENV_FILE="${RBTA_ENV_FILE:-${DEPLOY_DIR}/.env}"

echo "=== [Phase 1/9] Running Static Host Preflight Checks ==="
bash "${SCRIPT_DIR}/asus-preflight.sh"

get_env() {
  python3 "${SCRIPT_DIR}/read_env.py" "${ENV_FILE}" "$1" --default "${2:-}"
}
require_env() {
  python3 "${SCRIPT_DIR}/read_env.py" "${ENV_FILE}" "$1" --require
}

STATE_DIR=$(get_env "RBTA_STATE_HOST_DIR" "${ROOT_DIR}/state")
MODELS_DIR=$(get_env "RBTA_MODEL_HOST_DIR" "${ROOT_DIR}/models")
REPLAY_DIR=$(get_env "RBTA_REPLAY_HOST_DIR" "${ROOT_DIR}/data/replay")
MODEL_VERSION=$(require_env "RBTA_MODEL_VERSION")

echo "=== [Phase 2/9] Resolving Tested Code SHA Provenance & Ancestry ==="
STATE_JSON="${ROOT_DIR}/.agents/campaign/STATE.json"
STATE_CODE_SHA=""
if [ -f "${STATE_JSON}" ]; then
  STATE_CODE_SHA=$(grep -oE '"code_sha_tested": "[^"]+"' "${STATE_JSON}" | cut -d '"' -f4 || true)
fi

CODE_SHA="${RBTA_CODE_SHA:-${STATE_CODE_SHA}}"
if [ -z "${CODE_SHA}" ]; then
  echo "ERROR: Cannot resolve tested Code SHA. Neither RBTA_CODE_SHA nor STATE.json code_sha_tested is set." >&2
  exit 1
fi

if [ "${VERIFY_ONLY}" != "true" ] && [ -n "${STATE_CODE_SHA}" ] && [ "${CODE_SHA}" != "${STATE_CODE_SHA}" ]; then
  echo "ERROR: Provided RBTA_CODE_SHA '${CODE_SHA}' does not match STATE.json code_sha_tested '${STATE_CODE_SHA}'." >&2
  exit 1
fi

echo "Verifying git ancestry of CODE_SHA=${CODE_SHA}..."
if ! git -C "${ROOT_DIR}" merge-base --is-ancestor "${CODE_SHA}" HEAD; then
  echo "ERROR: CODE_SHA ${CODE_SHA} is not an ancestor of current HEAD." >&2
  exit 1
fi

# Verify no code modifications occurred after tested Code SHA
POST_DIFFS=$(git -C "${ROOT_DIR}" diff --name-only "${CODE_SHA}..HEAD" || true)
for file_changed in ${POST_DIFFS}; do
  if [[ "${file_changed}" != docs/evidence/* ]] && [ "${file_changed}" != ".agents/campaign/STATE.json" ]; then
    echo "ERROR: Untested code file '${file_changed}' was modified after tested CODE_SHA '${CODE_SHA}'!" >&2
    echo "       A new tested Code SHA is required." >&2
    exit 1
  fi
done
echo "✓ Tested CODE_SHA verified and clean: ${CODE_SHA}"

echo "=== [Phase 3/9] Generating Immutable Image Tag & Build Metadata ==="
IMAGE_TAG="sha-${CODE_SHA:0:12}"
BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
IMAGE_NAME="rbta-service:${IMAGE_TAG}"

export RBTA_CODE_SHA="${CODE_SHA}"
export RBTA_IMAGE_TAG="${IMAGE_TAG}"
export RBTA_BUILD_DATE="${BUILD_DATE}"
echo "✓ Target Image: ${IMAGE_NAME} (Built: ${BUILD_DATE})"

echo "=== [Phase 4/9] Building Production Container Image ==="
SKIP_BUILD="${RBTA_SKIP_BUILD:-0}"
if [ "${SKIP_BUILD}" = "1" ] && docker image inspect "${IMAGE_NAME}" >/dev/null 2>&1; then
  echo "Notice: RBTA_SKIP_BUILD=1 and image ${IMAGE_NAME} exists; skipping rebuild."
else
  docker compose --env-file "${ENV_FILE}" -f "${DEPLOY_DIR}/compose.yml" build
fi

echo "=== [Phase 5/9] Verifying OCI Revision Image Provenance ==="
if ! IMG_LABEL=$(docker inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision"}}' "${IMAGE_NAME}" 2>/dev/null); then
  echo "ERROR: Failed to inspect image ${IMAGE_NAME}" >&2
  exit 1
fi

if [ -z "${IMG_LABEL}" ] || [ "${IMG_LABEL}" != "${CODE_SHA}" ]; then
  echo "ERROR: Image revision label '${IMG_LABEL:-<empty>}' does not match expected CODE_SHA '${CODE_SHA}'" >&2
  exit 1
fi
echo "✓ OCI Image revision provenance verified: ${IMG_LABEL}"

echo "=== [Phase 6/9] Running Container Runtime Validation as UID 10001 ==="
docker run --rm \
  --user "10001:10001" \
  -v "${MODELS_DIR}:/app/artifacts/models:ro" \
  -v "${REPLAY_DIR}:/app/data/replay:ro" \
  -v "${STATE_DIR}:/app/data/runtime:rw" \
  -e "RBTA_MODEL_VERSION=${MODEL_VERSION}" \
  -e "RBTA_MODEL_REGISTRY_DIR=/app/artifacts/models" \
  -e "RBTA_REPLAY_DATA_DIR=/app/data/replay" \
  -e "RBTA_STATE_DIR=/app/data/runtime" \
  "${IMAGE_NAME}" \
  python -m src.deploy.runtime_validation
echo "✓ Container runtime validation passed: Model RO, Replay RO & Canonical, State RW & atomic rename"

echo "=== [Phase 7/9] Running Isolated Mutating Engineering Smoke ==="
RBTA_ENV_FILE="${ENV_FILE}" RBTA_IMAGE_TAG="${IMAGE_TAG}" bash "${SCRIPT_DIR}/smoke-isolated.sh"

if [ "${VERIFY_ONLY}" = "true" ]; then
  echo ""
  echo "=========================================================================="
  echo ">>> VERIFY-ONLY PASSED: All deployment phases (1-7) validated cleanly. <<<"
  echo "=========================================================================="
  exit 0
fi

echo "=== [Phase 8/9] Starting Production Service ==="
docker compose --env-file "${ENV_FILE}" -f "${DEPLOY_DIR}/compose.yml" up -d

echo "=== [Phase 9/9] Probing Health & Running Read-Only Smoke Gates ==="
PORT=$(require_env "RBTA_HOST_PORT")
MAX_RETRIES=30
RETRY_COUNT=0

echo -n "Waiting for /ready probe on port ${PORT}..."
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
  if curl -s -f "http://127.0.0.1:${PORT}/ready" >/dev/null 2>&1; then
    echo " OK!"
    break
  fi
  echo -n "."
  sleep 1
  RETRY_COUNT=$((RETRY_COUNT + 1))
done

if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
  echo " FAILED: /ready returned non-200 or timed out"
  docker compose --env-file "${ENV_FILE}" -f "${DEPLOY_DIR}/compose.yml" logs --tail=50
  exit 1
fi

echo "Running full read-only smoke suite..."
RBTA_ENV_FILE="${ENV_FILE}" bash "${SCRIPT_DIR}/smoke.sh"

echo ""
echo "=========================================================================="
echo ">>> ASUS DEPLOYMENT SUCCESSFUL: All Gates and Observability Checks Passed <<<"
echo "=========================================================================="
docker compose --env-file "${ENV_FILE}" -f "${DEPLOY_DIR}/compose.yml" ps
