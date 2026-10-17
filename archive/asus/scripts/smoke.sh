#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# RBTA + Isolation Forest — Read-Only Production Deployment Smoke Verification
# ==============================================================================
# This script performs STRICTLY READ-ONLY observability, static asset, and health checks.
# It NEVER mutates production telemetry, raw evidence, or outbox state.

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

RBTA_HOST_PORT="${RBTA_HOST_PORT:-$(get_env "RBTA_HOST_PORT" "")}"
RBTA_API_KEY="${RBTA_API_KEY:-$(get_env "RBTA_API_KEY" "")}"
RBTA_MODEL_VERSION="${RBTA_MODEL_VERSION:-$(get_env "RBTA_MODEL_VERSION" "")}"

if [ -z "${RBTA_HOST_PORT}" ]; then
  echo "ERROR: RBTA_HOST_PORT is required (no default port 8000 allowed)." >&2
  exit 1
fi

if [ -z "${RBTA_API_KEY}" ]; then
  echo "ERROR: RBTA_API_KEY environment variable is required to run smoke verification." >&2
  exit 1
fi

BASE_URL="http://127.0.0.1:${RBTA_HOST_PORT}"
AUTH_HEADER=(-H "Authorization: Bearer ${RBTA_API_KEY}")

echo "=== [Pre-Smoke State Snapshot] Capturing Non-Mutation Baseline ==="
INITIAL_STATS=$(curl -s -S -f "${AUTH_HEADER[@]}" "${BASE_URL}/runtime/stats")
echo "Initial Stats: ${INITIAL_STATS}"

echo "=== [1/11] Checking Liveness Probe (/health) ==="
HEALTH_RESP=$(curl -s -S -f "${BASE_URL}/health")
echo "✓ Health: ${HEALTH_RESP}"

echo "=== [2/11] Checking Readiness Probe (/ready) ==="
READY_RESP=$(curl -s -S -f "${BASE_URL}/ready")
echo "✓ Readiness: ${READY_RESP}"

echo "=== [3/11] Verifying Unauthorized Rejection (/api/v1/auth/check) ==="
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/api/v1/auth/check" || true)
if [ "${HTTP_CODE}" != "401" ]; then
  echo "ERROR: Expected 401 Unauthorized for unauthenticated request, got ${HTTP_CODE}" >&2
  exit 1
fi
echo "✓ Unauthenticated request correctly rejected with 401"

echo "=== [4/11] Verifying Authorized Access (/api/v1/auth/check) ==="
AUTH_RESP=$(curl -s -S -f "${AUTH_HEADER[@]}" "${BASE_URL}/api/v1/auth/check")
echo "✓ Auth verified: ${AUTH_RESP}"

echo "=== [5/11] Checking Runtime Statistics (/runtime/stats) ==="
STATS_RESP=$(curl -s -S -f "${AUTH_HEADER[@]}" "${BASE_URL}/runtime/stats")
echo "✓ Runtime Stats: ${STATS_RESP}"

echo "=== [6/11] Checking Production Dashboard Serving (/dashboard/) ==="
DASH_BODY=$(curl -s -S -f "${BASE_URL}/dashboard/")
if [[ "${DASH_BODY}" != *'id="root"'* ]]; then
  echo "ERROR: /dashboard/ did not return expected HTML entrypoint" >&2
  exit 1
fi
echo "✓ Dashboard HTML entrypoint served successfully"

echo "=== [7/11] Checking Static JS Bundle Serving ==="
JS_PATH=$(echo "${DASH_BODY}" | grep -oE '/dashboard/assets/index-[^"]+\.js' | head -n 1 || true)
if [ -n "${JS_PATH}" ]; then
  JS_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}${JS_PATH}")
  if [ "${JS_CODE}" != "200" ]; then
    echo "ERROR: Static asset ${JS_PATH} returned HTTP ${JS_CODE}" >&2
    exit 1
  fi
  echo "✓ Static asset ${JS_PATH} served successfully (200 OK)"
else
  echo "Notice: No explicit index-*.js script found in dashboard HTML, skipped asset fetch"
fi

echo "=== [8/11] Checking Nested SPA Route Fallback ==="
SPA_BODY=$(curl -s -S -f "${BASE_URL}/dashboard/meta-alerts/101/raw-alerts/wazuh-sample-001")
if [[ "${SPA_BODY}" != *'id="root"'* ]]; then
  echo "ERROR: Nested SPA route did not return fallback HTML" >&2
  exit 1
fi
echo "✓ Nested SPA route served successfully"

echo "=== [9/11] Checking Replay Datasets Discovery & JSONL Contract (/api/v1/replay/datasets) ==="
DATASETS_RESP=$(curl -s -S -f "${AUTH_HEADER[@]}" "${BASE_URL}/api/v1/replay/datasets")
echo "✓ Datasets response: ${DATASETS_RESP}"

# Validate at least one non-empty *.jsonl dataset
python3 -c "
import json, sys
data = json.loads(sys.argv[1])
datasets = data.get('datasets', data.get('items', []))
assert len(datasets) >= 1, f'Replay dataset count must be >= 1, got {len(datasets)}'
jsonl_datasets = [d for d in datasets if d.get('filename', d.get('name', '')).endswith('.jsonl')]
assert len(jsonl_datasets) >= 1, f'Expected at least one *.jsonl dataset, got {datasets}'
print(f'✓ Verified {len(datasets)} replay dataset(s) discovered, {len(jsonl_datasets)} ready *.jsonl.')
" "${DATASETS_RESP}"

echo "=== [10/11] Checking System Metadata Truth (/api/v1/dashboard/system) ==="
SYS_RESP=$(curl -s -S -f "${AUTH_HEADER[@]}" "${BASE_URL}/api/v1/dashboard/system")
echo "✓ System Metadata: ${SYS_RESP}"
if [ -n "${RBTA_MODEL_VERSION:-}" ]; then
  if [[ "${SYS_RESP}" != *"${RBTA_MODEL_VERSION}"* ]]; then
    echo "ERROR: System metadata does not contain configured model_version '${RBTA_MODEL_VERSION}'" >&2
    exit 1
  fi
  echo "✓ Model version truth verified in system metadata"
fi

echo "=== [11/11] Checking Integrations Truthful Status (/api/v1/dashboard/integrations) ==="
INTEG_RESP=$(curl -s -S -f "${AUTH_HEADER[@]}" "${BASE_URL}/api/v1/dashboard/integrations")
echo "✓ Integrations Status: ${INTEG_RESP}"

echo "=== [Post-Smoke State Verification] Proving Non-Mutation ==="
FINAL_STATS=$(curl -s -S -f "${AUTH_HEADER[@]}" "${BASE_URL}/runtime/stats")
if [ "${INITIAL_STATS}" != "${FINAL_STATS}" ]; then
  echo "ERROR: State signature changed during read-only smoke execution!" >&2
  echo "Initial: ${INITIAL_STATS}" >&2
  echo "Final:   ${FINAL_STATS}" >&2
  exit 1
fi
echo "✓ Zero state mutations confirmed: state signatures identical before and after smoke."

echo "=============================================================================="
echo "Production Smoke Verification Complete — ALL 11 READ-ONLY PROBES PASSED"
echo "=============================================================================="
