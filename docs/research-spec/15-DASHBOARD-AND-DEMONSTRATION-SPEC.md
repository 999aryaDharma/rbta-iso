# Dashboard, Investigasi Raw Alert, dan Lapisan Demonstrasi Deterministik

## 1. Architectural Overview

Lapisan operator dan investigasi dibangun di atas runtime penelitian (ingestion, RBTA, fitur, model, evaluasi) tanpa mengubah metodologinya.

Komponen utamanya:
1. **RawAlertEvidenceStore**: Immutable SQLite persistence layer for full raw alert evidence, written strictly *before* core RBTA mutation during ingestion.
2. **RBTAEngine Observability**: Pure read-only snapshot methods (\snapshot_agents()\, \snapshot_buckets()\) enabling zero-mutation visibility into per-agent EMA adaptation and active bucket states.
3. **REST Dashboard APIs**: Secure, authenticated endpoints providing KPIs, time series reduction, agent/bucket introspection, paginated MetaAlert lists, raw alert member resolution, and single-alert forensic JSON view.
4. **Deterministic ReplayController**: Background playback engine with speed throttling, pause/resume/stop/reset controls, session isolation, and deterministic execution.
5. **Modern Single-Page Application (SPA)**: Cloudflare-inspired infrastructure dashboard built with React 18, TypeScript, Tailwind CSS v4, and TanStack Query.
6. **Multi-Stage Docker Packaging**: Multi-stage build producing an all-in-one container serving the SPA from FastAPI alongside REST endpoints with SPA fallback routing.

---

## 2. Research Integrity & Invariant Preservation

Lapisan ini tunduk pada invarian penelitian yang dikunci:
- **Zero Alert Drops**: All valid incoming events are preserved without timestamp or watermark drops.
- **Evidence-Before-Mutation Order**: Raw alert evidence is persisted to the SQLite store prior to mutating the RBTA aggregation bucket.
- **Authoritative Backend Calculation**: The frontend never calculates ARR, feature normalization, anomaly scores, or quadrant decisions.
- **Idempotency**: Duplicate alerts identified by \wazuh_alert_id\ are safely deduplicated in the evidence store via \INSERT OR IGNORE\.

---

## 3. API Contract & Endpoints

| Endpoint | Method | Purpose | Auth |
| :--- | :--- | :--- | :--- |
| \/health\ | GET | Lightweight liveness probe | None |
| \/ready\ | GET | Readiness validating active model artifact | None |
| \/api/v1/dashboard/summary\ | GET | Top-level KPI counts, ARR, reduction rate | Bearer |
| \/api/v1/dashboard/agents\ | GET | Snapshot of per-agent EMA temporal states | Bearer |
| \/api/v1/dashboard/buckets\ | GET | Snapshot of currently open temporal buckets | Bearer |
| \/api/v1/dashboard/timeseries\ | GET | Time-aggregated raw vs meta alert series | Bearer |
| \/api/v1/dashboard/system\ | GET | Runtime readiness, model version & calibration | Bearer |
| \/api/v1/meta-alerts\ | GET | Paginated MetaAlerts list with filters & sorting | Bearer |
| \/api/v1/meta-alerts/{id}/raw-alerts\ | GET | Paginated member alerts for a MetaAlert | Bearer |
| \/api/v1/raw-alerts/{alert_id}\ | GET | Single raw alert record with JSON metadata | Bearer |
| \/api/v1/replay/status\ | GET | Real-time replay telemetry and playback state | Bearer |
| \/api/v1/replay/start\ | POST | Initiate background replay run | Bearer |
| \/api/v1/replay/pause\ | POST | Pause active replay stream | Bearer |
| \/api/v1/replay/resume\ | POST | Resume paused replay stream | Bearer |
| \/api/v1/replay/stop\ | POST | Terminate active replay run | Bearer |
| \/api/v1/replay/reset\ | POST | Reset replay controller to IDLE | Bearer |

---

## 4. Verification Suite

Cakupan unit dan integration test untuk lapisan ini:
- Raw alert persistence, idempotency, search filters, and partial resolution.
- RBTAEngine snapshot correctness across empty and active states.
- FastAPI dashboard route governance, auth validation, and pagination.
- Deterministic replay lifecycle, state transitions, and thread safety.
- Regresi penuh atas seluruh test suite backend.
