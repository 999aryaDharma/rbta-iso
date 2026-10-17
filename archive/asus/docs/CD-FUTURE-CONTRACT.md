# Future Continuous Deployment (CD) Operational Contract

## 1. Overview & Separation of Concerns

Continuous Integration (CI) and Continuous Deployment (CD) are strictly separated:

- **CI (`.github/workflows/ci.yml`)**: Fully automated on every `push` and `pull_request`. Runs the full test suite regression on Python 3.11, validates repository cleanliness, validates the Docker Compose contract with safe placeholders, performs a clean `--no-cache` Docker build, verifies non-root runtime UID (10001), and tests the `/health` endpoint.
- **CD (Future Operational Session)**: Operator-triggered, manual-approval release mechanism executing upon confirmed campus ASUS server network routes and Wazuh SIEM connectivity.

---

## 2. Future CD Workflow Parameters

When the ASUS server and Wazuh network route are confirmed, the future CD workflow will accept the following structured inputs:

| Parameter | Type | Required | Description |
|---|---|---|---|
| `git_sha` | string | Yes | Exact immutable 40-character Git commit SHA to deploy. |
| `model_version` | string | Yes | Explicit active model version folder (e.g. `seminar-final-v1`). |
| `target_environment` | choice | Yes | Target host (e.g. `asus-production`). |
| `force_recreate` | boolean | No | Whether to force recreate application container. |
| `rollback_sha` | string | No | Previous known-good Git commit SHA for automated rollback. |

---

## 3. Server Connectivity & Host Security Boundary

1. **Connection Method**: Secure deployment agent via self-hosted GitHub Actions runner on ASUS server or isolated Tailscale / WireGuard overlay network.
2. **Secret Storage**: Production `RBTA_API_KEY`, Wazuh credentials, and TLS certificates injected strictly at runtime on the server via `deploy/asus/.env` (mode `0600`). No secrets stored in GitHub repository.
3. **Model Artifact Distribution**: Immutable model bundle pre-staged under `/srv/rbta-iso/models/<model_version>` with valid `manifest.json`.

---

## 4. Automated Execution Sequence

```text
[Operator Dispatch]
        │
        ▼
[Preflight Validation]
  ├── Verify git_sha exists on origin
  ├── Validate deploy/asus/.env (RBTA_API_KEY, RBTA_MODEL_VERSION)
  ├── Validate model bundle manifest checksums (scripts/deploy/validate_model.py)
  └── Check host state directory permissions (10001:10001, 0750)
        │
        ▼
[Safe State Snapshot]
  └── cp state/state.json state/state.json.bak.$(date +%s)
        │
        ▼
[Container Lifecycle]
  ├── docker compose --env-file .env -f deploy/asus/compose.yml build
  └── docker compose --env-file .env -f deploy/asus/compose.yml up -d
        │
        ▼
[Automated Verification Gates]
  ├── Poll /health == 200 (Process Liveness)
  ├── Poll /ready == 200 (Scoring Pipeline Active)
  └── Run scripts/deploy/smoke.sh (Authenticated Smoke Probe)
        │
        ├── All PASS ──> [DEPLOYMENT COMPLETED & LOGGED]
        │
        └── Any FAIL ──> [AUTOMATED ROLLBACK & ALERT SOC]
```

---

## 5. Rollback Procedure

If `/ready` fails to reach HTTP 200 within 60 seconds or smoke tests fail:
1. Revert container image to `rollback_sha`.
2. Restore previous `state.json` backup if schema migrated.
3. Restart previous container: `docker compose up -d`.
4. Verify `/health` and `/ready` return HTTP 200 on the restored version.
