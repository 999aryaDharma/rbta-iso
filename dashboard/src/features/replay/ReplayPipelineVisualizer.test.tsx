import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { ReplayPipelineVisualizer } from './ReplayPipelineVisualizer';
import type { ReplayStatus, PipelineTelemetry } from '@/api/schemas';

describe('ReplayPipelineVisualizer component', () => {
  const mockStatus: ReplayStatus = {
    run_id: 'test-run-123',
    status: 'RUNNING',
    dataset: 'eval_dataset.jsonl',
    processed_count: 124500,
    total_count: 200000,
    progress: 0.6225,
    current_event_time: '2026-08-29T10:00:00Z',
    wall_clock_elapsed_seconds: 45.2,
    speed: 'MAX',
    events_per_second: 2750.5,
    model_version: 'rbta-if-v1',
  };

  const mockTelemetry: PipelineTelemetry = {
    raw: {
      processed: 124500,
      evidence_count: 124500,
      last_alert: { alert_id: 'alt-999', rule_group: 'sshd' },
    },
    rbta: {
      active_buckets: 7,
      finalized_meta_alerts: 8202,
      active_agents: 3,
    },
    latest_meta_alert: {
      meta_id: 8202,
      agent_id: '001',
      agent_name: 'prod-agent',
      rule_group_primary: 'sshd',
      alert_count: 17,
      max_severity: 9,
      anomaly_score: 0.411967,
      threshold_used: 0.402877,
      decision: 'CRITICAL',
      action: 'ESCALATE',
    },
    decision_counts: {
      ESCALATE: 238,
      SUPPRESS: 1482,
    },
    output: {
      telegram_deferred_count: 238,
    },
  };

  it('renders all 9 pipeline stages and triggers onSelectStage', () => {
    const handleSelect = vi.fn();
    render(
      <ReplayPipelineVisualizer
        status={mockStatus}
        telemetry={mockTelemetry}
        activeStage="RBTA"
        onSelectStage={handleSelect}
      />
    );

    expect(screen.getByText('1. Dataset')).toBeDefined();
    expect(screen.getByText('2. Standarisasi')).toBeDefined();
    expect(screen.getByText('3. Bukti asli')).toBeDefined();
    expect(screen.getByText('4. Jendela RBTA')).toBeDefined();
    expect(screen.getByText('5. Meta-alert')).toBeDefined();
    expect(screen.getByText('6. 7 fitur')).toBeDefined();
    expect(screen.getByText('7. IsoForest')).toBeDefined();
    expect(screen.getByText('8. Level')).toBeDefined();
    expect(screen.getByText('9. Keluaran')).toBeDefined();

    expect(screen.getByText('Berjalan')).toBeDefined();

    const featuresNode = screen.getByText('6. 7 fitur');
    fireEvent.click(featuresNode);
    expect(handleSelect).toHaveBeenCalledWith('FEATURES');
  });
});
