import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { PipelineStageDetail } from './PipelineStageDetail';
import type { PipelineTelemetry, ReplayStatus } from '@/api/schemas';

describe('PipelineStageDetail component', () => {
  const mockTelemetry: PipelineTelemetry = {
    raw: { processed: 1000, evidence_count: 1000 },
    rbta: { active_buckets: 2, finalized_meta_alerts: 50, active_agents: 1 },
    latest_meta_alert: {
      meta_id: 50,
      agent_id: '001',
      agent_name: 'prod-wazuh',
      rule_group_primary: 'authentication_failed',
      alert_count: 10,
      max_severity: 8,
      anomaly_score: 0.45,
      threshold_used: 0.40,
      margin: 0.05,
      decision: 'CRITICAL',
      action: 'ESCALATE',
      seven_features: {
        max_severity: 8.0,
        mitre_tactic_count: 2.0,
        critical_mitre_tactic_present: 1.0,
        alert_count_log: 2.3025,
        rule_diversity_shannon: 0.693,
        severity_dispersion: 0.5,
        agent_criticality: 2.0,
      },
    },
    output: {
      telegram_deferred_count: 5,
      latest_payload: {
        run_id: 'test-run',
        meta_id: 50,
        action: 'ESCALATE',
        message: 'Test message',
      },
    },
  };

  const mockStatus: ReplayStatus = {
    run_id: 'test-run',
    status: 'RUNNING',
    dataset: 'test.jsonl',
    processed_count: 1000,
    total_count: 1000,
    progress: 1.0,
    current_event_time: '2026-08-29T10:00:00Z',
    wall_clock_elapsed_seconds: 10,
    speed: 'MAX',
    events_per_second: 100,
    model_version: 'rbta-if-v1',
  };

  it('renders 7-features table without an internal horizontal scroll area', () => {
    const { container } = render(
      <PipelineStageDetail
        activeStage="FEATURES"
        telemetry={mockTelemetry}
        status={mockStatus}
      />
    );

    expect(screen.getByText('max_severity')).toBeDefined();
    expect(screen.getByText('mitre_tactic_count')).toBeDefined();
    expect(screen.getByText('critical_mitre_tactic_present')).toBeDefined();
    expect(screen.getByText('alert_count_log')).toBeDefined();
    expect(container.querySelector('.overflow-x-auto')).toBeNull();
  });

  it('renders model calibration and threshold margin when activeStage is DECISION', () => {
    render(
      <PipelineStageDetail
        activeStage="DECISION"
        telemetry={mockTelemetry}
        status={mockStatus}
      />
    );

    expect(screen.getByText(/Batas skor & tindakan/i)).toBeDefined();
    expect(screen.getByText(/\+0.050000/)).toBeDefined();
  });
});
