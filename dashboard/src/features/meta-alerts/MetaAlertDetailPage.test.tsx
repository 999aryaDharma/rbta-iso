import '@testing-library/jest-dom/vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it, vi, beforeEach } from 'vitest';
import { MetaAlertDetailPage } from './MetaAlertDetailPage';

const { mockFetchMetaAlert } = vi.hoisted(() => ({
  mockFetchMetaAlert: vi.fn(),
}));

vi.mock('@/api/metaAlerts', () => ({
  fetchMetaAlert: mockFetchMetaAlert,
  fetchMetaAlertTrace: vi.fn(),
}));

class ResizeObserverMock {
  observe() {}
  unobserve() {}
  disconnect() {}
}

vi.stubGlobal('ResizeObserver', ResizeObserverMock);

const detail = {
  meta_id: 5,
  agent_id: '005',
  agent_name: 'rbta-arya',
  rule_group_primary: 'rootcheck',
  start_time: '2026-10-03T01:00:00Z',
  end_time: '2026-10-03T02:00:00Z',
  alert_count: 49,
  max_severity: 7,
  mitre_tactics: [],
  anomaly_score: 0.42,
  threshold_used: 0.4,
  decision: 'CRITICAL',
  action: 'ESCALATE',
  model_version: 'rbta-if-v1',
  seven_features: {
    max_severity: 7,
    mitre_tactic_count: 0,
    critical_mitre_tactic_present: 0,
    alert_count_log: 1.69,
    rule_diversity_shannon: 0,
    severity_dispersion: 0,
    agent_criticality: 1,
  },
};

function renderAt(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/meta-alerts/:metaId" element={<MetaAlertDetailPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('MetaAlertDetailPage contract states', () => {
  it('menampilkan error + coba lagi saat detail gagal dimuat', async () => {
    mockFetchMetaAlert.mockRejectedValue(new Error('boom'));
    renderAt('/meta-alerts/5');
    expect(await screen.findByRole('alert')).toHaveTextContent(/gagal/i);
    fireEvent.click(screen.getByRole('button', { name: /coba lagi/i }));
    await waitFor(() => expect(mockFetchMetaAlert).toHaveBeenCalledTimes(2));
  });

  it('menampilkan state ID tidak valid', async () => {
    mockFetchMetaAlert.mockResolvedValue(detail);
    renderAt('/meta-alerts/bukan-angka');
    expect(await screen.findByText(/tidak valid/i)).toBeInTheDocument();
    expect(mockFetchMetaAlert).not.toHaveBeenCalled();
  });

  it('menampilkan ringkasan agregasi + skor saat sukses', async () => {
    mockFetchMetaAlert.mockResolvedValue(detail);
    renderAt('/meta-alerts/5');
    expect(await screen.findByText('MetaAlert #5')).toBeInTheDocument();
    expect(screen.getByText(/Temporal Aggregation Profile/)).toBeInTheDocument();
    expect(screen.queryByText(/Provenance Trace/)).not.toBeInTheDocument();
  });
  it('menampilkan penyebab deviasi robust bila tersedia', async () => {
    mockFetchMetaAlert.mockResolvedValue({
      ...detail,
      raw_model_score: 0.5,
      escalate: true,
      feature_schema_version: '1.0',
      score_calibration_version: 'minmax-v1',
      source_alert_ids: [],
      top_deviations: [['mitre_tactic_count', 4], ['rule_diversity_shannon', 2.1]],
    });
    renderAt('/meta-alerts/5');
    expect(await screen.findByText('mitre_tactic_count +4.0, rule_diversity_shannon +2.1')).toBeInTheDocument();
  });
});
