# RBTA + Isolation Forest Dashboard Design System

**Project:** RBTA + Isolation Forest untuk Mitigasi Alert Fatigue pada Log Keamanan SIEM Wazuh
**Status:** Design System / UI Source of Truth
**Frontend Stack:** React + TypeScript + Vite + Tailwind CSS v4 + @cloudflare/kumo + @phosphor-icons/react + TanStack Table + TanStack Query

---

## Cloudflare 2026 Visual & Interaction Refresh

### Conceptual Basis & Principles
The 2026 visual and interaction refresh adopts key architectural patterns from modern Cloudflare control planes:
1. **Kumo Visual Language**: Crisp neutral backgrounds (`#f7f7f8` light, `#121316` dark), 7px card radii, subtle 1px border lines (`#e2e5e9` / `#2d3139`), and purposeful accent usage without neon SOC clutter.
2. **Task-Oriented Navigation**: Grouping operational workflows into logical user tasks rather than internal Python module names:
   - `OVERVIEW` (System Overview & Needs Investigation)
   - `INVESTIGATE` (MetaAlerts & RBTA Engine)
   - `DEMONSTRATE` (Deterministic Replay Controller)
   - `OPERATIONS` (Integrations & System Health)
3. **Actionable Overview**: Immediate visual hierarchy prioritizing urgent escalations ("Needs Investigation") before long-term trend lines.
4. **Context-Preserving Deep Links**: Clicking KPI metrics (e.g. Escalated MetaAlerts, Agent ID) transitions directly into prefiltered investigative views while preserving the `run_id` context parameter.
5. **Multi-Mode Appearance**: Light, Dark, and System theme support persisted locally in `localStorage`.
6. **Command Palette & Keyboard Shortcuts**: Quick search navigation (`/`), global shortcut modal (`?`), screen navigation (`g o`, `g m`, `g r`, `g p`, `g s`), and forensic paging (`[`, `]`).
7. **Offline-First Typography**: Elimination of external Google Fonts network calls in favor of a robust system sans-serif font stack.

---

## 1. Purpose

Dashboard ini adalah lapisan observability dan demonstrasi untuk sistem RBTA + Isolation Forest.

Dashboard **tidak boleh menjadi tempat implementasi algoritma penelitian**.

Frontend hanya:

- membaca state operasional,
- menampilkan metric yang sudah dihitung backend,
- menampilkan hasil RBTA,
- menampilkan seven-feature vector,
- menampilkan Isolation Forest score,
- menampilkan threshold dan decision,
- menampilkan provenance MetaAlert,
- menyediakan drill-down dari MetaAlert ke raw alert,
- mengontrol replay melalui API yang deterministic,
- menampilkan status integrasi downstream.

Frontend **dilarang** menghitung ulang:

- EMA,
- baseline gap,
- current delta-t,
- Rule-Based Temporal Aggregation,
- seven features,
- RobustScaler,
- Isolation Forest score,
- Tukey threshold,
- decision matrix,
- Alert Reduction Rate,
- ground-truth classification metrics.

Semua angka penelitian yang tampil harus datang dari backend sebagai source of truth.

---

# 2. Core UX Principle

## 2.1 Traceability First

Setiap hasil agregasi harus dapat ditelusuri kembali ke alert pembentuknya.

```text
MetaAlert
    ↓
source_alert_ids[]
    ↓
Raw Alert List
    ↓
Raw Alert Detail
    ↓
Original / Canonical Evidence
```

Untuk decision `ESCALATE`, investigator harus dapat:

1. membuka MetaAlert;
2. melihat jumlah raw alert yang terkandung;
3. melihat seluruh raw alert satu per satu;
4. mencari alert tertentu;
5. memfilter berdasarkan rule, severity, timestamp, srcip, atau MITRE;
6. membuka detail setiap raw alert;
7. berpindah ke alert sebelumnya/berikutnya tanpa kembali ke daftar;
8. melihat canonical fields;
9. melihat source/audit metadata;
10. melihat original payload jika backend menyediakannya;
11. menyalin Alert ID atau field tertentu;
12. kembali ke MetaAlert tanpa kehilangan filter/context.

**Tidak boleh ada decision ESCALATE yang hanya menampilkan `source_alert_ids` tanpa akses investigasi lebih lanjut.**

---

# 3. Raw Alert Evidence Contract

## 3.1 Architectural Requirement

MetaAlert tetap menyimpan reference IDs, bukan duplikasi seluruh raw payload.

```text
ScoredMetaAlert
└── source_alert_ids[]
        │
        ├── wazuh-id-001 ──► RawAlertEvidence
        ├── wazuh-id-002 ──► RawAlertEvidence
        └── wazuh-id-003 ──► RawAlertEvidence
```

Raw evidence harus disimpan atau diakses melalui operational audit boundary terpisah.

UI tidak boleh bergantung pada internal private fields Python.

## 3.2 Required Read-Only Endpoints

```http
GET /api/v1/meta-alerts
GET /api/v1/meta-alerts/{meta_id}
GET /api/v1/meta-alerts/{meta_id}/trace
GET /api/v1/meta-alerts/{meta_id}/raw-alerts
GET /api/v1/raw-alerts/{wazuh_alert_id}
```

Pagination:

```http
GET /api/v1/meta-alerts/{meta_id}/raw-alerts?page=1&page_size=50
```

Optional filters:

```text
search
rule_id
level_min
level_max
srcip
mitre_tactic
from
to
```

## 3.3 Raw Alert Detail DTO

Minimum UI fields:

```text
wazuh_alert_id
timestamp
agent_id
agent_name
rule_id
rule_level
rule_description
rule_group_primary
rule_groups_all
mitre_tactics
mitre_techniques
srcip
location
decoder
full_log
agent_criticality
metadata
```

Where available:

```text
original_source_payload
opensearch_index
opensearch_document_id
source_mode
ingested_at
```

Raw DTO adalah **audit representation**, bukan research feature contract baru.

## 3.4 Evidence Preservation

Recommended:

```text
RawAlertEvidenceStore
    key = wazuh_alert_id
```

Boleh menyimpan:

- canonical alert snapshot;
- audit metadata;
- sanitized source envelope;
- original payload jika aman dan memang diperlukan.

Dilarang:

- mengubah perilaku RBTA;
- membuat canonicalization path kedua;
- memakai evidence store sebagai hidden feature source untuk IF.

## 3.5 Sensitive Data

Raw logs dapat mengandung data sensitif.

Default:

- redact password/token/authorization/secret-like keys;
- redact obvious API tokens;
- display redaction badge;
- copy hanya field yang tampil;
- JSON viewer read-only;
- API authentication tetap wajib.

---

# 4. Visual Identity

## 4.1 Direction

Gunakan estetika **Cloudflare-inspired infrastructure dashboard**:

- light-first;
- white / warm-neutral surfaces;
- thin borders;
- restrained shadows;
- compact navigation;
- strong hierarchy;
- orange product accent;
- blue primary action;
- dense but readable tables;
- operational, bukan decorative;
- minimal gradients;
- hampir tanpa glassmorphism;
- tanpa neon SOC aesthetic;
- tanpa oversized rounded cards.

Interface harus terasa seperti control plane / infrastructure console, bukan landing page.

## 4.2 Keywords

```text
Precise
Operational
Trustworthy
Traceable
Dense
Calm
Readable
Fast
Research-first
Cloud-infrastructure
```

---

# 5. Color System

## Light Theme — Default

```css
:root {
  --bg-app: #f7f7f8;
  --bg-surface: #ffffff;
  --bg-subtle: #f3f4f6;
  --bg-muted: #eceef1;
  --bg-hover: #f7f8fa;

  --text-primary: #111827;
  --text-secondary: #4b5563;
  --text-tertiary: #6b7280;
  --text-disabled: #9ca3af;
  --text-inverse: #ffffff;

  --border-default: #e2e5e9;
  --border-strong: #cfd4da;
  --border-subtle: #edf0f2;

  --brand-orange: #f6821f;
  --brand-orange-hover: #e76f0d;
  --brand-orange-soft: #fff3e8;

  --action-blue: #0055dc;
  --action-blue-hover: #0047b8;
  --action-blue-soft: #edf5ff;

  --success: #16803c;
  --success-soft: #eaf8ef;
  --warning: #b86500;
  --warning-soft: #fff7e6;
  --danger: #c93434;
  --danger-soft: #fff0f0;
  --info: #2563eb;
  --info-soft: #eff6ff;
}
```

## Dark Theme — Secondary

```css
.dark {
  --bg-app: #111214;
  --bg-surface: #181a1d;
  --bg-subtle: #202226;
  --bg-muted: #282b30;
  --bg-hover: #24272b;

  --text-primary: #f4f4f5;
  --text-secondary: #c7c9ce;
  --text-tertiary: #989ca3;
  --text-disabled: #6e737b;
  --text-inverse: #111214;

  --border-default: #30343a;
  --border-strong: #41464e;
  --border-subtle: #25282d;

  --brand-orange: #ff9a3c;
  --brand-orange-hover: #ffad61;
  --brand-orange-soft: #3a2414;

  --action-blue: #5b9cff;
  --action-blue-hover: #75acff;
  --action-blue-soft: #17243a;
}
```

Orange:

- product identity,
- current navigation marker,
- selected highlight,
- raw alert chart series.

Blue:

- primary actions,
- links,
- focus,
- MetaAlert chart series.

Status colors tidak boleh dipakai tanpa label teks/icon.

---

# 6. Typography

Primary:

```text
Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif
```

Monospace:

```text
JetBrains Mono, SFMono-Regular, Consolas, monospace
```

Use monospace untuk:

- Wazuh ID,
- Meta ID,
- model version,
- hash,
- JSON,
- raw log,
- technical timestamp.

Scale:

```text
Display        28/34 semibold
Page title     24/30 semibold
Section title  18/26 semibold
Card title     14/20 semibold
Body           14/21 regular
Small          13/18 regular
Caption        12/16 regular
Table          13/18 regular
Code           12–13/18
```

---

# 7. Spacing, Radius, Shadow

Base spacing unit: `4px`

```text
4, 8, 12, 16, 20, 24, 32, 40, 48
```

Defaults:

- card padding: 20–24px;
- table vertical cell padding: 9–11px;
- section gap: 24px;
- page section gap: 32px;
- toolbar gap: 8px.

Radius:

```text
xs 3px
sm 5px
md 7px
lg 10px
pill 999px
```

Default card radius: `7px`.

Cards memakai border, bukan shadow.

Popover/dialog boleh memakai:

```css
0 8px 24px rgba(0,0,0,.10)
```

---

# 8. App Shell

```text
┌───────────────────────────────────────────────────────────────────┐
│ Topbar                                                            │
├───────────────┬───────────────────────────────────────────────────┤
│ Sidebar       │ Breadcrumb / Page Header                         │
│               │                                                   │
│ Overview      │ Content                                           │
│ RBTA Engine   │                                                   │
│ MetaAlerts    │                                                   │
│ Replay        │                                                   │
│ Integrations  │                                                   │
│ System        │                                                   │
└───────────────┴───────────────────────────────────────────────────┘
```

Sidebar:

- desktop 240px;
- collapsed 64px;
- white surface;
- right border 1px.

Groups:

```text
MONITOR
- Overview
- RBTA Engine
- MetaAlerts

DEMONSTRATION
- Replay

OPERATIONS
- Integrations
- System
```

Active nav:

- orange left rail;
- subtle orange/neutral background;
- semibold label.

Topbar height: `56px`

Example:

```text
REPLAY   model-v3   ● READY                          ⟳   ◐
```

---

# 9. Routes

```text
/overview

/rbta
/rbta/agents/:agentId

/meta-alerts
/meta-alerts/:metaId
/meta-alerts/:metaId/raw-alerts
/meta-alerts/:metaId/raw-alerts/:alertId

/replay
/integrations
/system
```

Filters should use URL search params:

```text
/meta-alerts?decision=ESCALATE&agent=001&page=2
```

---

# 10. Overview Page

KPI row 1:

```text
Raw Alerts
MetaAlerts
Alert Reduction Rate
Escalated
```

KPI row 2:

```text
Active Agents
Active Buckets
Outbox Depth
Source / Replay State
```

Primary visual:

- Raw Alerts vs MetaAlerts over time;
- raw = orange;
- meta = blue;
- low-contrast grid;
- exact-value tooltip.

Decision Distribution:

- preferably compact horizontal stacked bar.

Latest MetaAlerts table:

```text
Meta ID
End Time
Agent
Rule Group
Raw Alerts
Severity
Anomaly Score
Decision
```

Every row navigates to detail.

---

# 11. RBTA Engine Page

Purpose:

> Observe backend-produced temporal state without recomputing it.

KPI:

- Active Agents
- Active Buckets
- Warmed-up Agents
- Seen Alerts

Agent table:

```text
Agent
Name
Events
Warmup
Baseline Gap
EMA Gap
Base Δt
Current Δt
Active Buckets
Status
```

Example:

```text
001  soc-01  421  100/100  12.4m  14.8m  15m  17.9m  3  ADAPTIVE
```

Before warmup, UI must not invent baseline/EMA values.

Agent detail:

- temporal summary;
- baseline;
- EMA;
- current Δt;
- event count;
- active bucket list;
- line chart.

---

# 12. MetaAlerts Page

Toolbar:

```text
Search
Decision
Agent
Rule Group
Severity
MITRE
Time Range
Columns
```

Table capabilities:

- resizable columns;
- hide/show columns;
- sticky header;
- sorting;
- pagination;
- advanced filters;
- compact row height;
- responsive fallback.

Default columns:

```text
Meta ID
Time
Agent
Rule Group
Raw Count
Max Severity
MITRE Tactics
Anomaly Score
Threshold
Decision
Model
```

ESCALATE badge:

```text
[ ! ESCALATE ]
```

SUPPRESS badge:

```text
[ SUPPRESS ]
```

---

# 13. MetaAlert Detail

Use dedicated route:

```text
/meta-alerts/:metaId
```

Header:

```text
MetaAlert #1402                     [ESCALATE]
Agent soc-01 · authentication
13 raw alerts · 12:21:02 → 12:31:18
```

Primary ESCALATE CTA:

```text
[ Investigate 13 Raw Alerts ]
```

Tabs:

```text
Overview
Seven Features
Raw Alerts (13)
Provenance
```

## Overview

Aggregation:

- Agent
- Rule Group
- Start
- End
- Duration
- Raw Alert Count
- Max Severity
- MITRE Tactics

Detection:

- Raw Model Score
- Anomaly Score
- Tukey Threshold
- Decision
- Action
- Model Version
- Feature Schema
- Calibration Version

## Seven Features

Exactly:

```text
max_severity
mitre_tactic_count
critical_mitre_tactic_present
alert_count_log
rule_diversity_shannon
severity_dispersion
agent_criticality
```

No browser-side computation.

---

# 14. Raw Alerts Tab — Mandatory

Toolbar:

```text
Search Alert ID / text
Rule ID
Severity
Source IP
MITRE
Timestamp
```

Table:

```text
#
Timestamp
Wazuh Alert ID
Rule ID
Level
Description
Source IP
MITRE
```

Click row → raw alert detail.

For ESCALATE, clicking **Investigate Raw Alerts** opens this tab.

---

# 15. Raw Alert Detail

Route:

```text
/meta-alerts/:metaId/raw-alerts/:alertId
```

Desktop:

```text
┌─────────────────────────────────────────────────────────────┐
│ Alert Header                                                │
├───────────────────────────────┬─────────────────────────────┤
│ Structured Fields             │ Raw / Source Evidence       │
│                               │                             │
│ timestamp                     │ JSON viewer                 │
│ agent                         │ full_log                    │
│ rule                          │ metadata                    │
│ severity                      │ original envelope           │
│ srcip                         │                             │
│ MITRE                         │                             │
└───────────────────────────────┴─────────────────────────────┘
```

Header:

```text
Raw Alert 4 of 13

1787895525.48425
2026-08-29 12:31:18 UTC

[ ← Previous ] [ Next → ]
```

Breadcrumb:

```text
MetaAlerts / #1402 / Raw Alerts / 1787895525.48425
```

Field groups:

### Identity

- Wazuh Alert ID
- Timestamp
- Source Mode
- Index
- Document ID

### Agent

- Agent ID
- Agent Name
- Criticality

### Rule

- Rule ID
- Level
- Description
- Primary Group
- All Groups

### Network

- Source IP
- destination/protocol when available

### MITRE

- Tactics
- Techniques
- IDs

### Audit

- Location
- Decoder
- Full Log
- Metadata

Raw JSON viewer:

- read-only;
- pretty print;
- collapse nodes;
- search;
- safe copy;
- redaction badge.

---

# 16. Raw Alert Investigation Split View

Desktop optional but recommended:

```text
┌──────────────────────────┬────────────────────────────────────┐
│ Raw Alert List           │ Selected Alert                    │
│                          │                                   │
│ 12:30 id-001 level 9     │ Rule 5503                         │
│ 12:31 id-002 level 10 ◀  │ Agent soc-01                      │
│ 12:31 id-003 level 7     │ MITRE Credential Access           │
│ ...                      │ full_log...                       │
└──────────────────────────┴────────────────────────────────────┘
```

List min width: `420px`.

Tablet/mobile uses dedicated detail route.

---

# 17. Provenance Tab

```text
MetaAlert #1402
│
├── Raw Alert id-001
├── Raw Alert id-002
├── Raw Alert id-003
├── Raw Alert id-004
└── Raw Alert id-005
```

This is traceability, not a decorative graph.

Large groups:

- search;
- virtualization if necessary;
- explicit unresolved IDs.

---

# 18. Replay Page

```text
Replay Run
Run ID: demo-2026-08-29-001
Dataset: wazuh-alerts.jsonl
```

Controls:

```text
[ Start ]
[ Pause ]
[ Resume ]
[ Stop ]

Speed:
1×  10×  100×  MAX

[ Reset as New Run ]
```

Rules:

- pause does not mutate event timestamps;
- resume continues deterministic replay;
- reset creates explicit new run;
- progress comes from backend.

Progress:

```text
68.4%
5,803 / 8,482
Historical Time: 2026-04-19 13:42:21 UTC
Wall Clock: 00:03:29
Speed: 27.7 events/s
```

Charts:

- raw rate;
- meta rate;
- ARR;
- active buckets.

---

# 19. Integration Page

```text
Wazuh Source
     ↓
RBTA
     ↓
Seven Features
     ↓
Isolation Forest
     ↓
Decision
     ↓
Outbox
     ↓
Shuffle
     ↓
Telegram
```

Statuses:

```text
READY
RUNNING
WAITING
DEGRADED
ERROR
DEFERRED
```

Never fake status.

Unknown Wazuh integration must render `DEFERRED`.

---

# 20. System Page

Compact definition lists:

```text
API Status
Runtime Readiness
Source Mode
Model Version
Feature Schema
Calibration Version
Threshold
Seen Alerts
Active Buckets
Outbox Depth
Current Run ID
```

---

# 21. Components

Base:

```text
AppShell
Sidebar
Topbar
Breadcrumb

Button
IconButton
LinkButton
Badge
StatusBadge
DecisionBadge

Card
MetricCard
StatList

Tabs
Popover
DropdownMenu
Tooltip
Sheet
Dialog

Input
SearchInput
Select
MultiSelect
DateRangeFilter
FilterChip

DataTable
ColumnManager
Pagination
EmptyState
Skeleton

LineChart
AreaChart
StackedBar
MiniSparkline

CodeViewer
JsonViewer
CopyField

Alert
Callout
Toast
```

Research-specific:

```text
SystemReadinessBadge
SourceModeBadge
ModelVersionBadge

AgentTemporalStateTable
TemporalStateChart
ActiveBucketTable

MetaAlertTable
MetaAlertHeader
MetaAlertSummary
SevenFeaturePanel
DetectionPanel
DecisionBadge

RawAlertTable
RawAlertHeader
RawAlertDetail
RawAlertFieldGroup
RawAlertJsonViewer
RawAlertSplitView
RawAlertNavigator

ReplayControls
ReplayProgress
ReplayClock

PipelineStatus
OutboxTable
```

---

# 22. Tables

Tables are first-class UI.

Desktop:

- 40–44px row;
- sticky header;
- compact text;
- horizontal scroll when necessary;
- resize;
- visibility controls;
- sort;
- pagination;
- URL filters;
- skeleton rows.

No zebra stripe by default.

Hover = subtle neutral.

Selected = blue-soft.

Escalate = subtle danger/orange left marker.

---

# 23. Charts

Rules:

- minimal grid;
- no 3D;
- no decorative gradient;
- exact tooltip;
- legend uses text + color;
- accessible colors;
- <=250ms animation;
- disable animation during MAX replay if needed.

Series:

```text
Raw Alerts    orange
MetaAlerts    blue
Threshold     muted red dashed
EMA           blue
Baseline      gray
Current Δt    orange
```

---

# 24. Buttons

Primary / blue:

- Start Replay
- Investigate Raw Alerts
- Apply Filters

Secondary:

- View Trace
- Columns
- Refresh

Ghost:

- row actions
- previous/next
- copy

Destructive:

- only actual destructive/reset operations;
- require confirmation where appropriate.

---

# 25. Accessibility

Target:

```text
WCAG 2.1 AA
```

Requirements:

- keyboard navigation;
- visible focus;
- status never color-only;
- semantic table headers;
- labelled controls;
- no constant screen-reader announcements from polling.

Focus:

```css
outline: 2px solid var(--action-blue);
outline-offset: 2px;
```

---

# 26. Responsive Behavior

Primary: `1280px+`

Also support:

- 1024px;
- 768px;
- mobile investigation.

Desktop:

- persistent sidebar;
- full table;
- raw split view.

Tablet:

- collapsible sidebar;
- horizontal tables;
- raw detail route.

Mobile:

- row-card fallback;
- no split view;
- raw investigation remains possible.

---

# 27. Frontend Stack

Required:

```text
React
TypeScript
Vite
Tailwind CSS v4
@cloudflare/kumo
@phosphor-icons/react
React Router
TanStack Query
TanStack Table
Recharts
Zod
```

Tests:

```text
Vitest
React Testing Library
Playwright
```

No Redux initially.

No Zustand initially unless there is a demonstrated need.

State:

- server = TanStack Query;
- filters = URL search params;
- transient UI = React local state.

---

# 28. Polling

Recommended:

```text
Overview summary      3s
Runtime status        3s
RBTA state            5s
Buckets               5s
MetaAlerts            5s
Outbox                5s
Replay status         1s while replaying
Raw detail            no periodic polling
```

Do not start with WebSocket.

SSE only if replay visualization later proves polling insufficient.

---

# 29. API Client Architecture

```text
dashboard/src/api/
├── client.ts
├── schemas.ts
├── dashboard.ts
├── rbta.ts
├── metaAlerts.ts
├── rawAlerts.ts
├── replay.ts
└── integrations.ts
```

Responses:

```text
API
↓
Zod validation
↓
typed DTO
↓
TanStack Query
↓
component
```

---

# 30. Feature Structure

```text
dashboard/
├── src/
│   ├── app/
│   ├── api/
│   ├── components/
│   │   ├── ui/
│   │   └── shared/
│   ├── features/
│   │   ├── overview/
│   │   ├── rbta/
│   │   ├── meta-alerts/
│   │   ├── raw-alerts/
│   │   ├── replay/
│   │   └── integrations/
│   ├── routes/
│   ├── hooks/
│   ├── lib/
│   ├── types/
│   └── styles/
├── package.json
└── vite.config.ts
```

Avoid giant `Dashboard.tsx`.

---

# 31. Backend Observability Contract

Recommended:

```text
GET /api/v1/dashboard/summary
GET /api/v1/dashboard/timeseries
GET /api/v1/dashboard/agents
GET /api/v1/dashboard/buckets
GET /api/v1/dashboard/system

GET /api/v1/meta-alerts
GET /api/v1/meta-alerts/{meta_id}
GET /api/v1/meta-alerts/{meta_id}/trace
GET /api/v1/meta-alerts/{meta_id}/raw-alerts
GET /api/v1/raw-alerts/{wazuh_alert_id}

GET /api/v1/replay/status
```

Replay controls:

```text
POST /api/v1/replay/start
POST /api/v1/replay/pause
POST /api/v1/replay/resume
POST /api/v1/replay/stop
POST /api/v1/replay/reset
```

Mutations limited to operational replay control.

---

# 32. Dashboard Summary DTO

```json
{
  "raw_alert_count": 12481,
  "meta_alert_count": 1492,
  "alert_reduction_rate": 0.8805,
  "escalate_count": 343,
  "suppress_count": 1149,
  "active_agents_count": 12,
  "active_buckets_count": 27,
  "outbox_depth": 4,
  "source_mode": "REPLAY",
  "model_version": "if-reference-v3",
  "ready": true,
  "updated_at": "2026-08-29T12:40:23Z"
}
```

ARR comes from backend.

---

# 33. Raw Alert Resolution DTO

```json
{
  "meta_id": 1402,
  "total": 13,
  "resolved_count": 13,
  "unresolved_alert_ids": [],
  "items": [
    {
      "wazuh_alert_id": "1787895525.48425",
      "timestamp": "2026-08-29T12:31:18Z",
      "agent_id": "001",
      "agent_name": "soc-01",
      "rule_id": "5501",
      "rule_level": 10,
      "rule_description": "Example description",
      "rule_group_primary": "authentication_failed",
      "mitre_tactics": ["Credential Access"],
      "srcip": "10.10.1.24"
    }
  ]
}
```

If:

```text
resolved_count != total
```

UI MUST show an evidence-resolution warning.

Never pretend all raw alerts are available when they are not.

---

# 34. MetaAlert Investigation Acceptance Criteria

```text
[ ] detail route works
[ ] source_alert_ids visible
[ ] Raw Alerts tab exists
[ ] raw count matches MetaAlert alert_count
[ ] every resolvable source ID opens detail
[ ] previous/next raw navigation works
[ ] raw search works
[ ] severity filter works
[ ] rule filter works
[ ] canonical fields visible
[ ] audit/source metadata visible
[ ] original payload visible if available
[ ] unresolved evidence explicitly reported
[ ] ESCALATE has Investigate Raw Alerts CTA
[ ] browser back preserves MetaAlert context
```

---

# 35. Decision UX

## ESCALATE

Must expose:

- strong decision badge;
- raw investigation CTA;
- anomaly score;
- threshold;
- provenance;
- seven features.

## SUPPRESS

Still fully investigable.

Suppressed MetaAlerts retain:

- detail;
- seven features;
- raw trace;
- raw investigation.

No result becomes inaccessible because it was suppressed.

---

# 36. Research Integrity Guardrails

Dashboard MUST NOT:

```text
calculate anomaly score
calculate seven features
calculate threshold
calculate EMA
calculate current delta-t
calculate ARR
change event timestamp
reinterpret decision
hide suppressed results permanently
drop old alerts
change model
train model
fit scaler
run sensitivity analysis
```

Dashboard MAY:

```text
sort
filter
paginate
search
format
group for visual presentation only
```

---

# 37. Security Guardrails

- API key never committed.
- Never render secrets intentionally.
- Raw JSON sanitized.
- Never render arbitrary HTML from `full_log`.
- Escape source strings.
- No `dangerouslySetInnerHTML`.
- Production CORS narrow.
- Dashboard cannot bypass API auth.

---

# 38. Loading, Errors, Empty States

Loading:

- skeleton per panel;
- no full-screen block if only one widget is loading.

Error:

```text
Could not load MetaAlerts

API returned 503.
Last successful update: 12:31:40

[ Retry ]
```

Empty:

```text
No MetaAlerts yet.
Start a replay or connect a source.
```

Raw unresolved:

```text
Raw alert evidence is unavailable for this source ID.
The source ID remains preserved in the MetaAlert trace.
```

---

# 39. Cloudflare-Inspired Rules

Use:

- left navigation;
- clean white surfaces;
- fine neutral borders;
- compact controls;
- powerful tables;
- restrained orange branding;
- blue links/actions;
- tight typography;
- operational status chips;
- chart + table combinations;
- responsive data views.

Avoid:

- Cloudflare logo/trademark reproduction;
- exact pixel clone;
- marketing hero;
- decorative illustration;
- giant rounded cards;
- glassmorphism;
- neon SOC visuals.

---

# 40. Visual Hierarchy

Priority:

```text
1. Decision / system state
2. Raw → MetaAlert reduction
3. Raw alert traceability
4. RBTA temporal state
5. Isolation Forest result
6. Replay controls
7. Integration state
```

For ESCALATE, the next obvious action must be:

```text
Investigate Raw Alerts
```

---

# 41. Recommended First Screen

```text
┌────────────────────────────────────────────────────────────────────────┐
│ RBTA Security Analytics                             REPLAY   ● READY    │
├───────────────┬────────────────────────────────────────────────────────┤
│ Overview      │ Overview                                               │
│ RBTA Engine   │                                                        │
│ MetaAlerts    │ Raw Alerts  12,481   MetaAlerts  1,492   ARR 88.05%   │
│ Replay        │ Escalated      343    Active Buckets 27               │
│ Integrations  │                                                        │
│ System        │ ┌────────────────────────┐ ┌─────────────────────────┐ │
│               │ │ Raw vs Meta over time  │ │ Decision Distribution   │ │
│               │ └────────────────────────┘ └─────────────────────────┘ │
│               │                                                        │
│               │ Latest MetaAlerts                                      │
│               │ #1402 soc-01 auth 13 raw 0.873 ESCALATE →            │
│               │ #1401 soc-03 sys   4 raw 0.321 SUPPRESS →            │
└───────────────┴────────────────────────────────────────────────────────┘
```

---

# 42. Definition of Done

```text
[ ] React + TypeScript + Vite structure
[ ] Tailwind v4 tokens implemented
[ ] Cloudflare-inspired light operational shell
[ ] official @cloudflare/kumo components implemented
[ ] Overview
[ ] RBTA Engine
[ ] MetaAlerts list
[ ] MetaAlert detail
[ ] Seven Features
[ ] Raw Alerts tab
[ ] Raw Alert detail
[ ] ESCALATE → Investigate Raw Alerts
[ ] unresolved evidence handled honestly
[ ] Replay UI
[ ] Integration/system status
[ ] frontend performs zero research calculations
[ ] accessibility tests
[ ] responsive layout
[ ] frontend tests
[ ] backend API tests
[ ] existing Python regression remains green
```

---

# 43. Final Design Rule

```text
A MetaAlert is never a dead-end summary.

Every MetaAlert must remain traceable to the Wazuh alerts that formed it.

ESCALATE means:
show why,
show the score,
show the seven features,
show the threshold,
and let the investigator inspect every raw alert one by one.
```
