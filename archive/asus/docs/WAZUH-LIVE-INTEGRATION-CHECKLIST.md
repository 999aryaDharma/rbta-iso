# Wazuh Live Integration Operational Checklist

> **2026-09-28 update:** The researcher selected the campus VPS as the deployment
> target. See [the current topology decision](LIVE-TOPOLOGY-DECISION.md).
> The ASUS references below describe the earlier topology. OS, private Indexer
> access, and credentials are still unconfirmed; no real smoke test is claimed.

This checklist tracks infrastructure, network, and scheduling parameters for the future live deployment session connecting the ASUS deployment instance to the campus Wazuh SIEM cluster.

> **Current Status:** All live integration fields remain **UNKNOWN** and **DEFERRED** until the physical deployment session. No live values are assumed or hardcoded into the application codebase.

---

## 1. Live Ingestion Source Mode Architecture

| Mode Option | Description | Status |
|---|---|---|
| **Option A: Indexer Live Poller** | ASUS application container actively polls Wazuh Indexer OpenSearch REST API (`/_search`) | `UNDECIDED` |
| **Option B: Collector Ingress Push** | Campus-side collector daemon tails local alert log (`alerts.json`) and POSTs into ASUS REST API (`/api/v1/alerts/ingest`) | `UNDECIDED` |

*Decision between Option A and Option B will be made during the infrastructure discovery phase based on campus firewall and network policies.*

---

## 2. Network & Routing Configuration

| Parameter | Status | Value | Evidence / Notes |
|---|---|---|---|
| **Wazuh Indexer Base URL** | `UNKNOWN` | | e.g. `https://<ip-or-domain>:9200` (Port 9200 candidate/to be confirmed) |
| **Network Path from ASUS Server** | `UNKNOWN` | | Direct LAN, VLAN routing, Tailscale, WireGuard, or SSH Tunnel |
| **Campus Firewall / ACL Openings** | `UNKNOWN` | | Port reachability to be confirmed during discovery session |
| **VPN / Overlay Tunnel Requirements** | `UNKNOWN` | | Tailscale/WireGuard service status on ASUS host |
| **Request Timeout & TCP Keepalive** | `UNKNOWN` | | Canonical client default: 30s timeout |

---

## 3. Authentication, TLS & Security

| Parameter | Status | Value | Evidence / Notes |
|---|---|---|---|
| **Authentication Mechanism** | `UNKNOWN` | | Basic Auth, Client Certs, or API Token |
| **Wazuh Service Account Username** | `UNKNOWN` | | Read-only security log analyst account |
| **Wazuh Service Account Password** | `UNKNOWN` | | Injected securely via `.env` / secret store |
| **TLS Certificate Verification Policy** | `UNKNOWN` | | Strict CA verification / Custom root CA bundle |
| **Custom CA / Certificate Path** | `UNKNOWN` | | Path to mounted PEM certificate on ASUS host |
| **Credential Storage Location** | `UNKNOWN` | | `/srv/rbta-iso/deploy/asus/.env` (mode `0600`) |

---

## 4. Indexer Schema & Data Retention

| Parameter | Status | Value | Evidence / Notes |
|---|---|---|---|
| **Actual Wazuh / OpenSearch Version** | `UNKNOWN` | | e.g. Wazuh 4.x / OpenSearch 2.x |
| **Daily Index Naming Pattern** | `UNKNOWN` | | e.g. `wazuh-alerts-4.x-YYYY.MM.DD` |
| **Index Retention Period (Days)** | `UNKNOWN` | | Total daily indices retained on Indexer cluster |
| **Minimum Required RBAC Permissions** | `UNKNOWN` | | `read` and `indices:data/read/search` on `wazuh-alerts-*` |
| **Sample Real Search Hit Payload** | `UNKNOWN` | | To be captured and verified against `CanonicalRawAlert` schema |

---

## 5. Operational Schedules (Canonical Code Defaults vs Production)

> **No-Drop Architecture Guarantee:** Recent reconciliation provides low-latency recovery for short network glitches, while full-retention reconciliation sweeps all retained source daily indices without timestamp drop boundaries. Old alerts are never dropped.

| Schedule Parameter | Current Code Default | Production Value | Status |
|---|---|---|---|
| **Fast Poll Interval** | `5 seconds` | `UNKNOWN` | `UNKNOWN` |
| **Recent Reconciliation Interval** | `5 minutes` | `UNKNOWN` | `UNKNOWN` |
| **Recent Reconciliation Coverage** | `2 daily indices` | `UNKNOWN` | `UNKNOWN` |
| **Full-Retention Reconciliation Interval** | `1 hour` | `UNKNOWN` | `UNKNOWN` |
| **Failure & Dead Letter Notification** | `Outbox queue persistence` | `UNKNOWN` | `UNKNOWN` |
| **Process Recovery Mode** | `Docker Compose restart: unless-stopped` | `UNKNOWN` | `UNKNOWN` |

---

## 6. Live Deployment Session Verification Gate

- [ ] Network reachability confirmed from ASUS container to Wazuh Indexer.
- [ ] TLS handshake succeeds with specified CA bundle.
- [ ] Read-only authentication verified against Wazuh Indexer.
- [ ] Search query returns actual daily index alert documents.
- [ ] `Canonicalizer` cleanly processes live alerts without schema validation errors.
- [ ] Full-retention reconciler scans all retained daily indices and recovers all historical alerts without drops.
