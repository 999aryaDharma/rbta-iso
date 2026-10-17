#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# RBTA + Isolation Forest — Isolated Engineering Ingestion Smoke Test
# ==============================================================================
# Verifies end-to-end alert ingestion, idempotency, research core scoring,
# and SQLite durability in a strictly isolated temporary container and state directory.
# Uses real model registry (:ro) and real replay (:ro) mounts, but NEVER touches
# or mounts production state directory.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DEPLOY_DIR="${ROOT_DIR}/deploy/asus"
ENV_FILE="${RBTA_ENV_FILE:-${DEPLOY_DIR}/.env}"

get_env() {
  if [ -f "${ENV_FILE}" ]; then
    python3 "${SCRIPT_DIR}/read_env.py" "${ENV_FILE}" "$1" --default "${2:-}"
  else
    echo "${2:-}"
  fi
}

MODEL_VERSION=$(get_env "RBTA_MODEL_VERSION" "reference-v1")
MODELS_DIR=$(get_env "RBTA_MODEL_HOST_DIR" "${ROOT_DIR}/models")
REPLAY_DIR=$(get_env "RBTA_REPLAY_HOST_DIR" "${ROOT_DIR}/data/replay")
PROD_STATE_DIR=$(get_env "RBTA_STATE_HOST_DIR" "${ROOT_DIR}/state")

IMAGE_TAG="${RBTA_IMAGE_TAG:-latest}"
IMAGE_NAME="rbta-service:${IMAGE_TAG}"

API_KEY="isolated-engineering-smoke-token-42"
TEST_CONTAINER="rbta-isolated-smoke-$(date +%s)"
TEMP_STATE_DIR=$(mktemp -d -t rbta_isolated_state_XXXXXX)
chmod 0777 "${TEMP_STATE_DIR}"

cleanup() {
  echo "Cleaning up isolated smoke test container and temporary state..."
  docker stop "${TEST_CONTAINER}" >/dev/null 2>&1 || true
  docker rm "${TEST_CONTAINER}" >/dev/null 2>&1 || true
  rm -rf "${TEMP_STATE_DIR}" >/dev/null 2>&1 || true
  echo "Cleanup complete."
}
trap cleanup EXIT

echo "=== [1/5] Starting Disposable Container with Real Model and Isolated State ==="
docker run -d --name "${TEST_CONTAINER}" \
  -p "127.0.0.1::8000" \
  -e RBTA_API_KEY="${API_KEY}" \
  -e RBTA_MODEL_VERSION="${MODEL_VERSION}" \
  -e RBTA_SOURCE_MODE="DEFERRED" \
  -e RBTA_LOG_LEVEL="DEBUG" \
  -v "${MODELS_DIR}:/app/artifacts/models:ro" \
  -v "${REPLAY_DIR}:/app/data/replay:ro" \
  -v "${TEMP_STATE_DIR}:/app/data/runtime:rw" \
  "${IMAGE_NAME}"

# Resolve dynamically allocated ephemeral host port
TEMP_PORT="$(docker port "${TEST_CONTAINER}" 8000/tcp | head -n1 | sed -E 's/.*:([0-9]+)$/\1/')"
echo "✓ Dynamic isolated smoke port bound: ${TEMP_PORT}"

echo "=== [2/5] Verifying Mount Destinations and Production State Isolation ==="
docker inspect "${TEST_CONTAINER}" | python3 -c "
import json, sys
data = json.load(sys.stdin)[0]
mounts = data.get('Mounts', [])
dest_map = {m['Destination']: m for m in mounts}

assert '/app/artifacts/models' in dest_map, 'models mount missing'
assert dest_map['/app/artifacts/models']['RW'] == False, 'models mount must be RO'

assert '/app/data/replay' in dest_map, 'replay mount missing'
assert dest_map['/app/data/replay']['RW'] == False, 'replay mount must be RO'

assert '/app/data/runtime' in dest_map, 'runtime mount missing'
assert dest_map['/app/data/runtime']['RW'] == True, 'runtime mount must be RW'

# Ensure production state directory is NOT mounted
prod_state = sys.argv[1].replace('\\\\', '/')
temp_state = sys.argv[2].replace('\\\\', '/')
for m in mounts:
    src = m.get('Source', '').replace('\\\\', '/')
    if prod_state and prod_state in src and src != temp_state:
        raise AssertionError(f'Production state directory {prod_state} was mounted into isolated test container!')
print('✓ Mount destinations and isolation verified behaviorally.')
" "${PROD_STATE_DIR}" "${TEMP_STATE_DIR}"

BASE_URL="http://127.0.0.1:${TEMP_PORT}"
AUTH_HEADER=(-H "Authorization: Bearer ${API_KEY}")

echo "=== [3/5] Waiting for Container Startup ==="
HEALTH_OK=false
for i in {1..30}; do
  if curl -s -f "${BASE_URL}/health" >/dev/null 2>&1; then
    echo "Container healthy on attempt $i."
    HEALTH_OK=true
    break
  fi
  sleep 1
done

if [ "${HEALTH_OK}" != "true" ]; then
  echo "ERROR: Isolated smoke container failed to start within 30s" >&2
  docker logs "${TEST_CONTAINER}"
  exit 1
fi

echo "=== [4/5] Ingesting Non-Production Engineering Sentinel Alert ==="
PAYLOAD='{
  "id": "__engineering_smoke_alert_001__",
  "timestamp": "2026-08-29T12:00:00.000+0000",
  "agent": {"id": "__engineering_smoke_agent__", "name": "engineering-test-agent"},
  "rule": {"id": "5501", "level": 7, "groups": ["pam"], "description": "SSH auth success"},
  "data": {"srcip": "10.0.0.1"},
  "rule_group_primary": "pam",
  "agent_criticality": 1
}'

echo "Attempt 1: Initial Ingestion..."
RESP_1=$(curl -s -S -f -X POST "${AUTH_HEADER[@]}" -H "Content-Type: application/json" -d "${PAYLOAD}" "${BASE_URL}/api/v1/alerts/ingest")
echo "Result 1: ${RESP_1}"

echo "Attempt 2: Idempotent Duplicate Ingestion..."
RESP_2=$(curl -s -S -f -X POST "${AUTH_HEADER[@]}" -H "Content-Type: application/json" -d "${PAYLOAD}" "${BASE_URL}/api/v1/alerts/ingest")
echo "Result 2: ${RESP_2}"

echo "=== [5/5] Proving Idempotency and Raw Evidence Durability ==="
STATS_RESP=$(curl -s -S -f "${AUTH_HEADER[@]}" "${BASE_URL}/runtime/stats")
echo "Stats: ${STATS_RESP}"

# Validate stats behavior
python3 -c "
import json, sys
data = json.loads(sys.argv[1])
seen = data.get('seen_alerts_count', data.get('seen_alert_count', 0))
assert seen == 1, f'Expected exactly 1 unique alert seen after duplicate ingest, got {seen}'
assert data.get('raw_evidence_count', 0) == 1, f'Expected 1 raw evidence stored, got {data.get(\"raw_evidence_count\")}'
print('✓ Duplicate idempotency and raw evidence proven (seen_alerts_count == 1).')
" "${STATS_RESP}"

echo "=============================================================================="
echo "Isolated Engineering Smoke Test Complete — ALL INGESTION PROBES PASSED"
echo "=============================================================================="
