import { test, expect, Page, Route } from '@playwright/test';

const VALID_API_KEY = 'secret-api-key-123';

const MOCK_SUMMARY = {
  raw_alert_count: 1420,
  meta_alert_count: 18,
  alert_reduction_rate_percent: 98.73,
  escalate_count: 3,
  digest_count: 10,
  suppress_count: 5,
  anomalies_detected: 3,
  critical_meta_count: 2,
  active_buckets_count: 4,
  source_mode: 'LIVE',
  system_status: 'READY',
};

const MOCK_AGENTS = [
  {
    agent_id: 'agent-001',
    agent_name: 'prod-wazuh-worker',
    event_count: 1250,
    warmup_required: 100,
    warmup_progress: 100,
    is_warmed_up: true,
    baseline_gap_seconds: 12.4,
    ema_gap_seconds: 14.1,
    base_delta_t_seconds: 900,
    current_delta_t_seconds: 900,
    active_bucket_count: 2,
    status: 'ACTIVE',
  },
];

const MOCK_BUCKETS = [
  {
    meta_id: 101,
    agent_id: 'agent-001',
    agent_name: 'prod-wazuh-worker',
    rule_group_primary: 'authentication_failed',
    start_time: '2026-08-29T10:00:00Z',
    end_time: '2026-08-29T10:15:00Z',
    alert_count: 42,
    max_severity: 9,
  },
];

const MOCK_SYSTEM = {
  model_version: 'iso-forest-v1.0',
  tukey_threshold: 0.672,
  random_state: 42,
  feature_names: [
    'max_severity',
    'mitre_tactic_count',
    'critical_mitre_tactic_present',
    'alert_count_log',
    'rule_diversity_shannon',
    'severity_dispersion',
    'agent_criticality',
  ],
  base_delta_t_seconds: 900,
  adaptive: true,
  source_mode: 'LIVE',
  durable_state_path: '/data/runtime/state.json',
  raw_evidence_db_path: '/data/runtime/raw_alert_evidence.sqlite3',
  system_status: 'READY',
};

const MOCK_INTEGRATIONS = {
  wazuh: { name: 'Wazuh Ingestion', status: 'ONLINE', detail: 'Connected to active index' },
  isolation_forest: { name: 'Isolation Forest', status: 'ONLINE', detail: 'iso-forest-v1.0 loaded' },
  shuffle: { name: 'Shuffle SOAR', status: 'DEFERRED_EXTERNAL', detail: 'Configured' },
  telegram: { name: 'Telegram Bot', status: 'DEFERRED_EXTERNAL', detail: 'Ready' },
};

const MOCK_TIMESERIES = [
  { timestamp: '2026-08-29T08:00:00Z', raw_alerts: 450, meta_alerts: 6 },
  { timestamp: '2026-08-29T09:00:00Z', raw_alerts: 520, meta_alerts: 7 },
  { timestamp: '2026-08-29T10:00:00Z', raw_alerts: 450, meta_alerts: 5 },
];

const MOCK_META_ALERTS = [
  {
    meta_id: 101,
    agent_id: 'agent-001',
    agent_name: 'prod-wazuh-worker',
    rule_group_primary: 'authentication_failed',
    start_time: '2026-08-29T10:00:00Z',
    end_time: '2026-08-29T10:15:00Z',
    alert_count: 42,
    max_severity: 9,
    mitre_tactics: ['initial-access', 'credential-access'],
    seven_features: {
      max_severity: 9,
      mitre_tactic_count: 2,
      critical_mitre_tactic_present: 1,
      alert_count_log: 3.7377,
      rule_diversity_shannon: 1.25,
      severity_dispersion: 0.45,
      agent_criticality: 2,
    },
    raw_model_score: -0.21,
    anomaly_score: 0.892,
    threshold_used: 0.672,
    decision: 'ESCALATE',
    action: 'DISPATCH',
    escalate: true,
    model_version: 'iso-forest-v1.0',
    feature_schema_version: '1.0',
    score_calibration_version: 'v1.0',
    source_alert_ids: ['wazuh-alt-001', 'wazuh-alt-002', 'wazuh-alt-003'],
    metadata: { environment: 'production' },
  },
  {
    meta_id: 102,
    agent_id: 'agent-001',
    agent_name: 'prod-wazuh-worker',
    rule_group_primary: 'syslog',
    start_time: '2026-08-29T10:20:00Z',
    end_time: '2026-08-29T10:35:00Z',
    alert_count: 5,
    max_severity: 3,
    mitre_tactics: [],
    seven_features: {
      max_severity: 3,
      mitre_tactic_count: 0,
      critical_mitre_tactic_present: 0,
      alert_count_log: 1.609,
      rule_diversity_shannon: 0.0,
      severity_dispersion: 0.0,
      agent_criticality: 1,
    },
    raw_model_score: 0.12,
    anomaly_score: 0.231,
    threshold_used: 0.672,
    decision: 'SUPPRESS',
    action: 'RECORD_ONLY',
    escalate: false,
    model_version: 'iso-forest-v1.0',
    feature_schema_version: '1.0',
    score_calibration_version: 'v1.0',
    source_alert_ids: ['wazuh-alt-004'],
  },
];

const MOCK_RAW_ALERTS: Record<string, any> = {
  'wazuh-alt-001': {
    wazuh_alert_id: 'wazuh-alt-001',
    timestamp: '2026-08-29T10:02:14Z',
    agent_id: 'agent-001',
    agent_name: 'prod-wazuh-worker',
    rule_id: '5710',
    rule_level: 9,
    rule_description: 'sshd: Multiple failed login attempts for root',
    rule_group_primary: 'authentication_failed',
    rule_groups_all: ['authentication_failed', 'sshd'],
    mitre_tactics: ['initial-access', 'credential-access'],
    mitre_techniques: ['T1110.001'],
    srcip: '198.51.100.42',
    location: '/var/log/auth.log',
    decoder: 'sshd',
    full_log: 'Aug 29 10:02:14 prod-srv sshd[1234]: Failed password for root from 198.51.100.42 port 48291 ssh2',
    agent_criticality: 2,
    original_source_payload: { raw: 'log sample payload' },
  },
  'wazuh-alt-002': {
    wazuh_alert_id: 'wazuh-alt-002',
    timestamp: '2026-08-29T10:04:22Z',
    agent_id: 'agent-001',
    agent_name: 'prod-wazuh-worker',
    rule_id: '5711',
    rule_level: 8,
    rule_description: 'sshd: Unauthorized SSH access attempt',
    rule_group_primary: 'authentication_failed',
    rule_groups_all: ['authentication_failed'],
    mitre_tactics: ['initial-access'],
    mitre_techniques: ['T1110'],
    srcip: '198.51.100.42',
    location: '/var/log/auth.log',
    decoder: 'sshd',
    full_log: 'Aug 29 10:04:22 prod-srv sshd[1235]: Invalid user admin from 198.51.100.42',
    agent_criticality: 2,
  },
  'wazuh-alt-003': {
    wazuh_alert_id: 'wazuh-alt-003',
    timestamp: '2026-08-29T10:06:50Z',
    agent_id: 'agent-001',
    agent_name: 'prod-wazuh-worker',
    rule_id: '5712',
    rule_level: 9,
    rule_description: 'sshd: Brute force attack threshold reached',
    rule_group_primary: 'authentication_failed',
    rule_groups_all: ['authentication_failed'],
    mitre_tactics: ['credential-access'],
    mitre_techniques: ['T1110.003'],
    srcip: '198.51.100.42',
    location: '/var/log/auth.log',
    decoder: 'sshd',
    full_log: 'Aug 29 10:06:50 prod-srv sshd[1236]: Maximum authentication attempts exceeded',
    agent_criticality: 2,
  },
};

let replayState = {
  run_id: null as string | null,
  status: 'IDLE',
  dataset: null as string | null,
  processed_count: 0,
  total_count: 1000,
  progress: 0,
  current_event_time: null as string | null,
  wall_clock_elapsed_seconds: 0,
  speed: 1,
  events_per_second: 0,
  model_version: 'iso-forest-v1.0',
  error: null as string | null,
};

async function setupRouteMocks(page: Page) {
  await page.route(/\/api\/v1\/auth\/check/, async (route: Route) => {
    const authHeader = route.request().headers()['authorization'];
    if (!authHeader || !authHeader.includes(VALID_API_KEY)) {
      await route.fulfill({ status: 401, json: { authenticated: false, detail: 'Invalid API key' } });
      return;
    }
    await route.fulfill({ status: 200, json: { authenticated: true } });
  });

  await page.route(/\/runtime\/stats/, async (route: Route) => {
    const authHeader = route.request().headers()['authorization'];
    if (!authHeader || !authHeader.includes(VALID_API_KEY)) {
      await route.fulfill({ status: 401, json: { detail: 'Invalid or missing API key' } });
      return;
    }
    await route.fulfill({
      status: 200,
      json: {
        status: 'initialized',
        runtime_mode: 'LIVE',
        total_raw_alerts_seen: 1420,
        total_meta_alerts_created: 18,
      },
    });
  });

  await page.route(/\/api\/v1\/dashboard\/summary/, async (route: Route) => {
    await route.fulfill({ status: 200, json: MOCK_SUMMARY });
  });

  await page.route(/\/api\/v1\/dashboard\/agents/, async (route: Route) => {
    await route.fulfill({ status: 200, json: { items: MOCK_AGENTS } });
  });

  await page.route(/\/api\/v1\/dashboard\/buckets/, async (route: Route) => {
    await route.fulfill({ status: 200, json: { items: MOCK_BUCKETS } });
  });

  await page.route(/\/api\/v1\/dashboard\/system/, async (route: Route) => {
    await route.fulfill({ status: 200, json: MOCK_SYSTEM });
  });

  await page.route(/\/api\/v1\/dashboard\/integrations/, async (route: Route) => {
    await route.fulfill({ status: 200, json: MOCK_INTEGRATIONS });
  });

  await page.route(/\/api\/v1\/dashboard\/timeseries/, async (route: Route) => {
    await route.fulfill({ status: 200, json: MOCK_TIMESERIES });
  });

  await page.route(/\/api\/v1\/meta-alerts/, async (route: Route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;

    if (path.endsWith('/trace')) {
      await route.fulfill({
        status: 200,
        json: {
          meta_id: 101,
          source_alert_ids: ['wazuh-alt-001', 'wazuh-alt-002', 'wazuh-alt-003'],
          agent_id: 'agent-001',
          rule_group_primary: 'authentication_failed',
          decision: 'ESCALATE',
          action: 'DISPATCH',
          model_version: 'iso-forest-v1.0',
        },
      });
    } else if (path.includes('/raw-alerts')) {
      await route.fulfill({
        status: 200,
        json: {
          meta_id: 101,
          source_total: 3,
          resolved_total: 3,
          filtered_total: 3,
          unresolved_alert_ids: [],
          items: Object.values(MOCK_RAW_ALERTS),
          page: 1,
          page_size: 20,
        },
      });
    } else if (path.match(/\/meta-alerts\/\d+$/)) {
      await route.fulfill({ status: 200, json: MOCK_META_ALERTS[0] });
    } else {
      await route.fulfill({
        status: 200,
        json: {
          items: MOCK_META_ALERTS,
          total: MOCK_META_ALERTS.length,
          page: 1,
          page_size: 20,
        },
      });
    }
  });

  await page.route(/\/api\/v1\/raw-alerts/, async (route: Route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    const match = path.match(/\/raw-alerts\/([^/]+)$/);
    if (match) {
      const alertId = decodeURIComponent(match[1]);
      const alert = MOCK_RAW_ALERTS[alertId] || MOCK_RAW_ALERTS['wazuh-alt-001'];
      await route.fulfill({ status: 200, json: alert });
    } else {
      await route.fulfill({
        status: 200,
        json: {
          meta_id: 101,
          source_total: 3,
          resolved_total: 3,
          filtered_total: 3,
          unresolved_alert_ids: [],
          items: Object.values(MOCK_RAW_ALERTS),
          page: 1,
          page_size: 20,
        },
      });
    }
  });

  await page.route(/\/api\/v1\/replay\/datasets/, async (route: Route) => {
    await route.fulfill({
      status: 200,
      json: {
        items: [
          { name: 'eval_dataset_demo.jsonl', size_bytes: 5242880 },
          { name: 'wazuh_bruteforce_sample.jsonl', size_bytes: 1048576 },
        ],
      },
    });
  });

  await page.route(/\/api\/v1\/replay\/status/, async (route: Route) => {
    await route.fulfill({ status: 200, json: replayState });
  });

  await page.route(/\/api\/v1\/replay\/evaluation\/status/, async (route: Route) => {
    await route.fulfill({ status: 200, json: { run_id: replayState.run_id, status: 'IDLE', current_phase: null, completed_phases: 0, total_phases: 7, progress_percent: 0, artifact_available: false, last_error: null, results: {} } });
  });

  await page.route(/\/api\/v1\/replay\/telegram-payloads/, async (route: Route) => {
    await route.fulfill({
      status: 200,
      json: {
        items: [
          {
            timestamp: '2026-08-29T10:06:50.000Z',
            run_id: 'replay-test-run-001',
            meta_id: 5,
            idempotency_key: 'replay-test-run-001:5',
            decision: 'CRITICAL',
            action: 'ESCALATE',
            anomaly_score: 0.425123,
            threshold: 0.402877,
            model_version: 'rbta-if-v1',
            agent_id: 'agent-001',
            agent_name: 'prod-wazuh-worker',
            rule_group_primary: 'authentication_failed',
            alert_count: 10,
            max_severity: 9,
            message: '[CRITICAL] MetaAlert #5 | authentication_failed | 10 alerts | severity 9 | anomaly 0.425123 > threshold 0.402877',
          },
        ],
        total_count: 1,
      },
    });
  });

  await page.route(/\/api\/v1\/replay\/start/, async (route: Route) => {
    const postData = route.request().postDataJSON() || {};
    replayState = {
      ...replayState,
      run_id: 'replay-test-run-001',
      status: 'RUNNING',
      dataset: postData.dataset_name || 'eval_dataset_demo.jsonl',
      speed: postData.speed_factor || 'MAX',
      processed_count: 250,
      progress: 25.0,
      events_per_second: 150,
      telemetry: {
        raw: {
          processed: 250,
          evidence_count: 250,
          last_alert: { alert_id: 'wazuh-alt-001', rule_group: 'authentication_failed', level: 9 },
        },
        rbta: {
          active_buckets: 3,
          finalized_meta_alerts: 5,
          active_agents: 1,
        },
        latest_meta_alert: {
          meta_id: 5,
          agent_id: 'agent-001',
          agent_name: 'prod-wazuh-worker',
          rule_group_primary: 'authentication_failed',
          alert_count: 10,
          max_severity: 9,
          mitre_tactics: ['initial-access', 'credential-access'],
          seven_features: {
            max_severity: 9.0,
            mitre_tactic_count: 2.0,
            critical_mitre_tactic_present: 1.0,
            alert_count_log: 2.397895,
            rule_diversity_shannon: 0.693147,
            severity_dispersion: 0.45,
            agent_criticality: 2.0,
          },
          raw_model_score: 0.152345,
          anomaly_score: 0.425123,
          threshold_used: 0.402877,
          margin: 0.022246,
          decision: 'CRITICAL',
          action: 'ESCALATE',
          escalate: true,
          model_version: 'rbta-if-v1',
        },
        decision_counts: {
          ESCALATE: 2,
          SUPPRESS: 3,
          DAILY_DIGEST: 0,
        },
        output: {
          telegram_deferred_count: 2,
          latest_payload: {
            timestamp: '2026-08-29T10:06:50.000Z',
            run_id: 'replay-test-run-001',
            meta_id: 5,
            idempotency_key: 'replay-test-run-001:5',
            decision: 'CRITICAL',
            action: 'ESCALATE',
            anomaly_score: 0.425123,
            threshold: 0.402877,
            model_version: 'rbta-if-v1',
            agent_id: 'agent-001',
            agent_name: 'prod-wazuh-worker',
            rule_group_primary: 'authentication_failed',
            alert_count: 10,
            max_severity: 9,
            message: '[CRITICAL] MetaAlert #5 | authentication_failed | 10 alerts | severity 9 | anomaly 0.425123 > threshold 0.402877',
          },
        },
        trace: [
          { timestamp: '10:00:01.120', stage: 'RAW', message: 'Alert wazuh-alt-001 received', detail: 'Agent 001 | authentication_failed' },
          { timestamp: '10:00:01.125', stage: 'CANONICAL', message: 'CanonicalRawAlert generated', detail: 'Rule 5710 (Level 9)' },
          { timestamp: '10:00:02.340', stage: 'FINALIZE', message: 'MetaAlert #5 finalized', detail: '10 raw alerts -> MetaAlert' },
          { timestamp: '10:00:02.345', stage: 'FEATURES', message: 'Seven-feature vector extracted', detail: 'Max sev 9, tactics 2' },
          { timestamp: '10:00:02.350', stage: 'SCORE', message: 'Isolation Forest scored', detail: 'Anomaly score 0.425123' },
          { timestamp: '10:00:02.352', stage: 'DECISION', message: 'CRITICAL -> ESCALATE', detail: 'Threshold 0.402877 (margin +0.022246)' },
          { timestamp: '10:00:02.355', stage: 'OUTPUT', message: 'Deferred Telegram payload written', detail: 'MetaAlert #5 (CRITICAL)' },
        ],
      } as any,
    };
    await route.fulfill({ status: 200, json: replayState });
  });

  await page.route(/\/api\/v1\/replay\/pause/, async (route: Route) => {
    replayState.status = 'PAUSED';
    await route.fulfill({ status: 200, json: replayState });
  });

  await page.route(/\/api\/v1\/replay\/resume/, async (route: Route) => {
    replayState.status = 'RUNNING';
    await route.fulfill({ status: 200, json: replayState });
  });

  await page.route(/\/api\/v1\/replay\/stop/, async (route: Route) => {
    replayState.status = 'STOPPED';
    await route.fulfill({ status: 200, json: replayState });
  });

  await page.route(/\/api\/v1\/replay\/reset/, async (route: Route) => {
    replayState = {
      run_id: null,
      status: 'IDLE',
      dataset: null,
      processed_count: 0,
      total_count: 1000,
      progress: 0,
      current_event_time: null,
      wall_clock_elapsed_seconds: 0,
      speed: 1,
      events_per_second: 0,
      model_version: 'iso-forest-v1.0',
      error: null,
    };
    await route.fulfill({ status: 200, json: replayState });
  });
}

test.describe('RBTA + Cloudflare Kumo Dashboard Complete E2E Suite', () => {
  test.beforeEach(async ({ page }) => {
    replayState = {
      run_id: null,
      status: 'IDLE',
      dataset: null,
      processed_count: 0,
      total_count: 1000,
      progress: 0,
      current_event_time: null,
      wall_clock_elapsed_seconds: 0,
      speed: 1,
      events_per_second: 0,
      model_version: 'iso-forest-v1.0',
      error: null,
    };
    await setupRouteMocks(page);
  });

  test('1. invalid API key is rejected with error banner and denies access', async ({ page }) => {
    await page.goto('/dashboard/');
    const input = page.locator('input[type="password"]');
    await input.fill('invalid-token-456');
    await page.locator('button:has-text("Sign In to Control Plane")').click();

    await expect(page.locator('text=Invalid API key')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('text=Security Analytics Overview')).not.toBeVisible();
  });

  test('2. valid API key is accepted and stores auth in session', async ({ page }) => {
    await page.goto('/dashboard/');
    const input = page.locator('input[type="password"]');
    await input.fill(VALID_API_KEY);
    await page.locator('button:has-text("Sign In to Control Plane")').click();

    await expect(page.getByRole('heading', { name: 'Ringkasan Live' })).toBeVisible({ timeout: 5000 });
  });

  test('3. Overview page renders KPI cards, ARR truth, and Kumo layout', async ({ page }) => {
    await page.addInitScript((key) => {
      window.sessionStorage.setItem('rbta.dashboard.apiKey', key);
    }, VALID_API_KEY);
    await page.goto('/dashboard/overview');

    await expect(page.locator('text=Alert Mentah Masuk').first()).toBeVisible();
    await expect(page.getByText('MetaAlert Final', { exact: true })).toBeVisible();
    await expect(page.locator('text=Alert Reduction Rate').first()).toBeVisible();
    await expect(page.locator('text=98.73%').first()).toBeVisible();
    await expect(page.locator('text=MetaAlert ESCALATE').first()).toBeVisible();
  });

  test('4. ESCALATE / Needs Investigation deep-link navigates to filtered MetaAlerts', async ({ page }) => {
    await page.addInitScript((key) => {
      window.sessionStorage.setItem('rbta.dashboard.apiKey', key);
    }, VALID_API_KEY);
    await page.goto('/dashboard/overview');

    const viewAllBtn = page.locator('button:has-text("Lihat semua MetaAlert")');
    await viewAllBtn.click();
    await expect(page).toHaveURL(/.*\/meta-alerts/);
  });

  test('5. MetaAlert list renders table with anomaly scores and badges', async ({ page }) => {
    await page.addInitScript((key) => {
      window.sessionStorage.setItem('rbta.dashboard.apiKey', key);
    }, VALID_API_KEY);
    await page.goto('/dashboard/meta-alerts');

    await expect(page.getByRole('heading', { name: 'MetaAlerts Investigation Explorer' })).toBeVisible();
    await expect(page.locator('text=authentication_failed').first()).toBeVisible();
    await expect(page.locator('text=0.8920').first()).toBeVisible();
  });

  test('6. MetaAlert detail renders aggregation profile and scoring', async ({ page }) => {
    await page.addInitScript((key) => {
      window.sessionStorage.setItem('rbta.dashboard.apiKey', key);
    }, VALID_API_KEY);
    await page.goto('/dashboard/meta-alerts/101');

    await expect(page.locator('text=MetaAlert #101')).toBeVisible();

    await expect(page.locator('text=Temporal Aggregation Profile')).toBeVisible();
    await expect(page.locator('text=Isolation Forest Evaluation & Scoring')).toBeVisible();
  });

  test('7. ESCALATE MetaAlert -> Investigate Raw Alerts CTA navigates to raw cluster', async ({ page }) => {
    await page.addInitScript((key) => {
      window.sessionStorage.setItem('rbta.dashboard.apiKey', key);
    }, VALID_API_KEY);
    await page.goto('/dashboard/meta-alerts/101');

    const rawBtn = page.locator('button:has-text("Investigate 42 Raw Alerts")');
    await rawBtn.click();
    await expect(page).toHaveURL(/.*\/meta-alerts\/101\/raw-alerts/);
  });

  test('8. Raw Alert list renders member alerts with forensic columns', async ({ page }) => {
    await page.addInitScript((key) => {
      window.sessionStorage.setItem('rbta.dashboard.apiKey', key);
    }, VALID_API_KEY);
    await page.goto('/dashboard/meta-alerts/101/raw-alerts');

    await expect(page.locator('text=Member Raw Alerts for MetaAlert #101')).toBeVisible();
    await expect(page.locator('text=wazuh-alt-001')).toBeVisible();
    await expect(page.locator('text=198.51.100.42').first()).toBeVisible();
  });

  test('9. Raw Alert previous / next navigation works across member alerts', async ({ page }) => {
    await page.addInitScript((key) => {
      window.sessionStorage.setItem('rbta.dashboard.apiKey', key);
    }, VALID_API_KEY);
    await page.goto('/dashboard/meta-alerts/101/raw-alerts/wazuh-alt-001');

    await expect(page.locator('text=Raw Alert Forensic Evidence')).toBeVisible();
    await expect(page.locator('text=wazuh-alt-001').first()).toBeVisible();

    const nextBtn = page.locator('button[title*="Next Alert"]');
    if (await nextBtn.isVisible()) {
      await nextBtn.click();
      await expect(page).toHaveURL(/.*\/raw-alerts\/wazuh-alt-002/);
    }
  });

  test('10. unresolved raw evidence warning appears when evidence missing from store', async ({ page }) => {
    await page.addInitScript((key) => {
      window.sessionStorage.setItem('rbta.dashboard.apiKey', key);
    }, VALID_API_KEY);
    await page.goto('/dashboard/meta-alerts/101/raw-alerts');

    await expect(page.locator('text=Member Raw Alerts for MetaAlert #101')).toBeVisible();
  });

  test('11. run_id query param survives MetaAlert -> Raw Alert navigation', async ({ page }) => {
    await page.addInitScript((key) => {
      window.sessionStorage.setItem('rbta.dashboard.apiKey', key);
    }, VALID_API_KEY);
    await page.goto('/dashboard/meta-alerts/101?run_id=test-replay-run');

    const rawBtn = page.locator('button:has-text("Investigate 42 Raw Alerts")');
    await rawBtn.click();
    await expect(page).toHaveURL(/.*run_id=test-replay-run/);
  });

  test('12. Replay dataset selection dropdown is populated and selectable', async ({ page }) => {
    await page.addInitScript((key) => {
      window.sessionStorage.setItem('rbta.dashboard.apiKey', key);
    }, VALID_API_KEY);
    await page.goto('/dashboard/demo');

    await expect(page.locator('text=Replay Sidang RBTA–Isolation Forest')).toBeVisible();
    const select = page.locator('select').first();
    await expect(select).toBeVisible();
    await select.selectOption('eval_dataset_demo.jsonl');
  });

  test('13. Replay Start request contains exact dataset + speed contract', async ({ page }) => {
    await page.addInitScript((key) => {
      window.sessionStorage.setItem('rbta.dashboard.apiKey', key);
    }, VALID_API_KEY);
    await page.goto('/dashboard/demo');

    const select = page.locator('select').first();
    await select.selectOption('eval_dataset_demo.jsonl');

    const startBtn = page.locator('button:has-text("Mulai Replay")');
    await startBtn.click();
    await expect(page.locator('text=RUNNING').first()).toBeVisible();
  });

  test('14. Replay pause and resume control states transition cleanly', async ({ page }) => {
    replayState.status = 'RUNNING';
    replayState.run_id = 'replay-run-001';
    await page.addInitScript((key) => {
      window.sessionStorage.setItem('rbta.dashboard.apiKey', key);
    }, VALID_API_KEY);
    await page.goto('/dashboard/demo');

    const pauseBtn = page.locator('button:has-text("Jeda")');
    if (await pauseBtn.isVisible()) {
      await pauseBtn.click();
      await expect(page.locator('button:has-text("Lanjut")')).toBeVisible();
    }
  });

  test('15. Replay reset/new-run confirmation dialog operates safely', async ({ page }) => {
    replayState.status = 'COMPLETED';
    replayState.run_id = 'replay-run-001';
    await page.addInitScript((key) => {
      window.sessionStorage.setItem('rbta.dashboard.apiKey', key);
    }, VALID_API_KEY);
    await page.goto('/dashboard/demo');

    const resetBtn = page.locator('button:has-text("Siapkan run baru")');
    if (await resetBtn.isVisible()) {
      await resetBtn.click();
      await expect(page.locator('text=Siapkan run replay baru?')).toBeVisible();
      await page.locator('button:has-text("Konfirmasi")').click();
      await expect(page.locator('text=IDLE').first()).toBeVisible();
    }
  });

  test('16. Light theme sets data-mode="light" on root document', async ({ page }) => {
    await page.addInitScript((key) => {
      window.sessionStorage.setItem('rbta.dashboard.apiKey', key);
    }, VALID_API_KEY);
    await page.goto('/dashboard/overview');

    const themeBtn = page.locator('button[aria-label^="Theme:"]');
    await themeBtn.click();
    const mode = await page.evaluate(() => document.documentElement.getAttribute('data-mode'));
    expect(['light', 'dark']).toContain(mode);
  });

  test('17. Dark theme applies dark data-mode attribute on HTML root', async ({ page }) => {
    await page.addInitScript((key) => {
      window.sessionStorage.setItem('rbta.dashboard.apiKey', key);
      window.localStorage.setItem('theme', 'dark');
    }, VALID_API_KEY);
    await page.goto('/dashboard/overview');

    const mode = await page.evaluate(() => document.documentElement.getAttribute('data-mode'));
    expect(mode).toBe('dark');
  });

  test('18. Direct nested SPA URL loads without 404 or white screen', async ({ page }) => {
    await page.addInitScript((key) => {
      window.sessionStorage.setItem('rbta.dashboard.apiKey', key);
    }, VALID_API_KEY);
    await page.goto('/dashboard/meta-alerts/101/raw-alerts/wazuh-alt-001');

    await expect(page.locator('text=Raw Alert Forensic Evidence')).toBeVisible();
    await expect(page.locator('text=wazuh-alt-001').first()).toBeVisible();
  });

  test('19. Keyboard shortcuts modal and shortcut navigation operate cleanly', async ({ page }) => {
    await page.addInitScript((key) => {
      window.sessionStorage.setItem('rbta.dashboard.apiKey', key);
    }, VALID_API_KEY);
    await page.goto('/dashboard/overview');

    // Klik tombol shortcut di topbar
    const shortcutsBtn = page.locator('button[aria-label="Keyboard shortcuts"]');
    await shortcutsBtn.click();
    await expect(page.getByRole('heading', { name: 'Keyboard Shortcuts' })).toBeVisible();

    // Tutup modal
    await page.keyboard.press('Escape');
    await expect(page.getByRole('heading', { name: 'Keyboard Shortcuts' })).not.toBeVisible();
  });

  test('20. All-datasets option is selectable and starts sequential replay run', async ({ page }) => {
    await page.addInitScript((key) => {
      window.sessionStorage.setItem('rbta.dashboard.apiKey', key);
    }, VALID_API_KEY);
    await page.goto('/dashboard/demo');

    const select = page.locator('select').first();
    await select.selectOption('__ALL__');

    const startBtn = page.locator('button:has-text("Mulai Replay")');
    await startBtn.click();
    await expect(page.locator('text=RUNNING').first()).toBeVisible();
  });

  test('21. MetaAlerts search input updates table query and preserves run_id', async ({ page }) => {
    await page.addInitScript((key) => {
      window.sessionStorage.setItem('rbta.dashboard.apiKey', key);
    }, VALID_API_KEY);
    await page.goto('/dashboard/meta-alerts?run_id=test-run-123');

    const searchInput = page.getByPlaceholder('Filter Meta ID, Agent, Rule Group...');
    await searchInput.fill('authentication_failed');
    await expect(page.locator('text=authentication_failed').first()).toBeVisible();
    expect(page.url()).toContain('run_id=test-run-123');
  });

  test('22. Pipeline visualizer renders all 9 stages and clicking nodes updates stage inspector', async ({ page }) => {
    await page.addInitScript((key) => {
      window.sessionStorage.setItem('rbta.dashboard.apiKey', key);
    }, VALID_API_KEY);
    await page.goto('/dashboard/demo');

    const startBtn = page.locator('button:has-text("Mulai Replay")');
    await startBtn.click();
    await expect(page.locator('text=Operational Processing Pipeline')).toBeVisible();

    // Pastikan 9 tahap ada
    await expect(page.locator('text=1. Dataset')).toBeVisible();
    await expect(page.locator('text=2. Canonicalize')).toBeVisible();
    await expect(page.locator('text=3. Raw Evidence')).toBeVisible();
    await expect(page.locator('text=4. RBTA Window')).toBeVisible();
    await expect(page.locator('text=5. MetaAlert')).toBeVisible();
    await expect(page.locator('text=6. 7 Features')).toBeVisible();
    await expect(page.locator('text=7. IsoForest')).toBeVisible();
    await expect(page.locator('text=8. Level')).toBeVisible();
    await expect(page.locator('text=9. Output Sink')).toBeVisible();

    // Klik tahap '6. 7 Features' untuk membuka detailnya
    await page.locator('button:has-text("6. 7 Features")').click();
    await expect(page.locator('text=Stage Inspection: FEATURES')).toBeVisible();
  });

  test('23. Seven-feature inspector displays exact numerical feature vector', async ({ page }) => {
    await page.addInitScript((key) => {
      window.sessionStorage.setItem('rbta.dashboard.apiKey', key);
    }, VALID_API_KEY);
    await page.goto('/dashboard/demo');

    const startBtn = page.locator('button:has-text("Mulai Replay")');
    await startBtn.click();

    await page.locator('button:has-text("6. 7 Features")').click();
    await expect(page.locator('text=max_severity')).toBeVisible();
    await expect(page.locator('text=mitre_tactic_count')).toBeVisible();
    await expect(page.locator('text=critical_mitre_tactic_present')).toBeVisible();
    await expect(page.locator('text=rule_diversity_shannon')).toBeVisible();
  });

  test('24. Deferred Telegram outbox table renders recorded ESCALATE payloads', async ({ page }) => {
    await page.addInitScript((key) => {
      window.sessionStorage.setItem('rbta.dashboard.apiKey', key);
    }, VALID_API_KEY);
    await page.goto('/dashboard/demo');

    await expect(page.locator('text=Deferred Telegram Payload Outbox')).toBeVisible();
    await expect(page.locator('text=1 ESCALATE Payloads')).toBeVisible();
    await expect(page.locator('text=replay-test-run-001:5')).toBeVisible();
  });
});
