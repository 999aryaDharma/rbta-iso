# ASUS Server Deployment Guide — RBTA + Isolation Forest Service

## 1. Operational Overview & Phased Deployment Model

To guarantee methodological integrity and prevent speculative operational claims, deployment to the ASUS server is structured into discrete phases:

```text
+-------------------------------------------------------------+
| Phase A: Repository & CI/CD Readiness (CURRENT: PASS)       |
|  - Full test suite passing (269+ unit/integration tests)    |
|  - Production Dockerfile (non-root UID 10001)               |
|  - Fail-closed Compose manifest (requires port, key, model) |
|  - Container runtime validator (src.deploy.runtime_validation)|
|  - Automated preflight & smoke scripts verified             |
+-------------------------------------------------------------+
                              │
                              ▼
+-------------------------------------------------------------+
| Phase B: Historical Replay Readiness (CURRENT: READY)       |
|  - Replay-only primary mode (RBTA_SOURCE_MODE=DEFERRED)     |
|  - Derived replay *.jsonl datasets mounted RO to container  |
|  - Model registry bundle mounted RO to container            |
|  - Immutable campus archives stored unmounted in archive/   |
+-------------------------------------------------------------+
                              │
                              ▼
+-------------------------------------------------------------+
| Phase C: Physical ASUS Deployment Execution (DEFERRED)      |
|  - Deploy immutable container revision on ASUS              |
|  - Execute asus-deploy.sh --verify-only                     |
|  - Launch production instance and verify read-only smoke    |
+-------------------------------------------------------------+
                              │
                              ▼
+-------------------------------------------------------------+
| Phase D: Future Live SIEM & SOAR Integration (DEFERRED)     |
|  - Wazuh live coordinator stream                            |
|  - Shuffle & Telegram downstream alert notification hooks   |
+-------------------------------------------------------------+
```

---

## 2. Directory Layout & Storage Architecture on ASUS Host

The ASUS host machine separates immutable archives, derived replay datasets, model artifacts, and durable runtime state:

```text
/srv/rbta-iso/
├── archive/                      <-- Original immutable compressed campus export (*.jsonl.gz, NOT mounted)
│    └── wazuh/
│         └── batch-*/
│              └── *.jsonl.gz
│
├── replay/                       <-- Derived replay-ready datasets (*.jsonl, mounted :ro)
│    └── research-dataset-v1.jsonl
│
├── models/                       <-- Versioned model registry (mounted :ro)
│    └── <RBTA_MODEL_VERSION>/
│         ├── isolation_forest.joblib
│         ├── robust_scaler.joblib
│         ├── score_calibration.json
│         ├── threshold.json
│         ├── feature_schema.json
│         ├── metadata.json
│         └── manifest.json
│
├── state/                        <-- Host-mounted RW durable state & raw evidence SQLite
│    ├── state.json
│    └── evidence.db
│
└── app/                          <-- Git repository clone (checkout on FINAL_HEAD)
     ├── deploy/asus/
     │    ├── compose.yml         <-- Production Docker Compose manifest
     │    └── .env                <-- Authoritative environment configuration
     └── scripts/deploy/
          ├── asus-preflight.sh
          ├── asus-deploy.sh
          ├── smoke.sh
          └── smoke-isolated.sh
```

### Storage Conceptual Distinction

- `archive/`: Original immutable compressed campus SIEM export (`*.jsonl.gz` / parts). Never modified, not mounted into the container.
- `replay/`: Derived, rebuildable plain `*.jsonl` datasets. Application input for `ReplayController`, mounted strictly **READ-ONLY (`:ro`)**.
- `models/`: Published versioned model artifacts. Mounted strictly **READ-ONLY (`:ro`)**.
- `state/`: Durable engine state, SQLite raw evidence store, and outbox queue. Mounted **READ-WRITE (`:rw`)**.

### Initial Host Directory Setup
```bash
mkdir -p /srv/rbta-iso/{archive,replay,models,state}

# Configure non-root container ownership (UID/GID 10001:10001) for state
sudo chown -R 10001:10001 /srv/rbta-iso/state
sudo chmod 0750 /srv/rbta-iso/state
```

---

## 3. Mandatory Environment Configuration

Copy `deploy/asus/.env.example` to `deploy/asus/.env`:

```bash
cp deploy/asus/.env.example deploy/asus/.env
chmod 0600 deploy/asus/.env
```

| Variable | Requirement | Description | Example / Notes |
|---|---|---|---|
| `RBTA_API_KEY` | **MANDATORY** | Secret token for `/api/v1/*` & `/runtime/stats`. Fail-closed if empty. | Random 32+ char token |
| `RBTA_MODEL_VERSION` | **MANDATORY** | Active model version subdirectory. Fail-closed if empty. | e.g. `reference-v1` |
| `RBTA_HOST_PORT` | **MANDATORY** | Loopback port bound on host (1024–65535, port 8000 disallowed). | `8010` |
| `RBTA_SOURCE_MODE` | **MANDATORY** | Alert input mode (`DEFERRED` for replay-only deployment). | `DEFERRED` |
| `RBTA_LOG_LEVEL` | Configurable | Log verbosity (`DEBUG`, `INFO`, `WARNING`). | `INFO` |
| `RBTA_STATE_HOST_DIR` | Configurable | Host path to state directory. | `/srv/rbta-iso/state` |
| `RBTA_MODEL_HOST_DIR` | Configurable | Host path to model registry directory. | `/srv/rbta-iso/models` |
| `RBTA_REPLAY_HOST_DIR`| Configurable | Host path to replay dataset directory. | `/srv/rbta-iso/replay` |

*Note: `RBTA_IMAGE_TAG` and `RBTA_BUILD_DATE` are generated deterministically by `asus-deploy.sh` based on the tested `CODE_SHA` from `.agents/campaign/STATE.json`.*

---

## 4. Deployment Execution Sequence

### Step 1: Checkout FINAL_HEAD
```bash
git fetch origin
git checkout fix/s11-asus-deployment-harness-final
```

### Step 2: Prepare Artifacts & Replay Dataset
1. Place published model bundle in `/srv/rbta-iso/models/<RBTA_MODEL_VERSION>/`.
2. Place at least one derived, non-empty `*.jsonl` replay dataset in `/srv/rbta-iso/replay/`.

### Step 3: Run Deployment Verification Harness (--verify-only)
```bash
bash scripts/deploy/asus-deploy.sh --verify-only
```
*Executes static host preflight, tested Code SHA resolution, Docker image build, OCI revision verification, container runtime validation as UID 10001 (`src.deploy.runtime_validation`), and isolated engineering smoke without starting production.*

### Step 4: Execute Full Production Deployment
```bash
bash scripts/deploy/asus-deploy.sh
```
*Launches production container via Docker Compose, probes `/ready` on the configured loopback port, and executes the 11 read-only smoke checks (asserting zero state mutation).*

---

## 5. Security & Invariant Baseline

- **Non-Root Runtime**: Strictly runs as `appuser:appgroup` (`UID 10001:10001`).
- **Dropped Capabilities**: `cap_drop: ALL`, `no-new-privileges: true`.
- **Immutable Mounts**: Model directory and Replay directory are mounted strictly read-only (`:ro`).
- **Network Isolation**: Binds strictly to host loopback (`127.0.0.1:${RBTA_HOST_PORT}`).
- **Bounded Logging**: Docker JSON logging capped at 10MB x 3 rotations.

---

## 6. Deferred Deployment Items

The following items remain intentionally marked **DEFERRED** pending external connectivity:

1. **Physical ASUS Hardware Deployment**: Real physical server execution. Status: **DEFERRED**.
2. **Live Wazuh Coordinator**: Real campus Wazuh cluster stream. Status: **DEFERRED**.
3. **Downstream Webhooks**: Shuffle and Telegram live alert notifications. Status: **DEFERRED_EXTERNAL**.
