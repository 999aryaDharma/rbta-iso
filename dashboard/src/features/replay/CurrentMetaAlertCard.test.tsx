import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { CurrentMetaAlertCard } from './CurrentMetaAlertCard';
import type { PipelineLatestMetaAlert } from '@/api/schemas';

describe('CurrentMetaAlertCard component', () => {
  const mockMeta: PipelineLatestMetaAlert = {
    meta_id: 8202,
    agent_id: '001',
    agent_name: 'prod-wazuh-agent',
    rule_group_primary: 'syscheck',
    alert_count: 17,
    max_severity: 7,
    anomaly_score: 0.411967,
    threshold_used: 0.402877,
    margin: 0.00909,
    decision: 'CRITICAL',
    action: 'ESCALATE',
    escalate: true,
    model_version: 'rbta-if-v1',
  };

  it('renders current scored MetaAlert details with reduction metrics', () => {
    render(
      <CurrentMetaAlertCard
        latestMeta={mockMeta}
        rawProcessed={124531}
        metaFinalized={8202}
        decisionCounts={{ ESCALATE: 238, SUPPRESS: 1482, DAILY_DIGEST: 119 }}
      />
    );

    expect(screen.getByText('#8202')).toBeDefined();
    expect(screen.getByText('syscheck')).toBeDefined();
    expect(screen.getByText(/17/)).toBeDefined();
    expect(screen.getByText(/93.4%/)).toBeDefined();
    expect(screen.getByText(/Perlu dicek segera: 238/)).toBeDefined();
  });

  it('renders waiting placeholder when no meta is finalized yet', () => {
    render(
      <CurrentMetaAlertCard
        latestMeta={null}
        rawProcessed={100}
        metaFinalized={0}
      />
    );

    expect(screen.getByText(/Menunggu kelompok alert pertama selesai diproses/i)).toBeDefined();
  });
});
