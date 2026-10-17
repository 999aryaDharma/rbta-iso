import '@testing-library/jest-dom/vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { describe, expect, it, vi, beforeEach } from 'vitest';
import { BucketDetailPage } from './BucketDetailPage';

const { mockFetchBuckets, mockFetchBucketRawAlerts } = vi.hoisted(() => ({
  mockFetchBuckets: vi.fn(),
  mockFetchBucketRawAlerts: vi.fn(),
}));

vi.mock('@/api/dashboard', () => ({
  fetchBuckets: mockFetchBuckets,
  fetchBucketRawAlerts: mockFetchBucketRawAlerts,
}));

function Probe() {
  const location = useLocation();
  return <p data-testid="path">{location.pathname}</p>;
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/live/buckets/005/rootcheck']}>
        <Routes>
          <Route path="/live/buckets/:agentId/:ruleGroup" element={<BucketDetailPage />} />
          <Route path="*" element={<Probe />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const member = {
  wazuh_alert_id: 'a1',
  timestamp: '2026-10-04T02:50:59+00:00',
  agent_id: '005',
  agent_name: 'rbta-arya',
  rule_id: '510',
  rule_level: 7,
  rule_description: 'Rootcheck event',
  rule_group_primary: 'rootcheck',
  rule_groups_all: ['rootcheck'],
  mitre_tactics: [],
  mitre_techniques: [],
  srcip: null,
  agent_criticality: 1,
};

beforeEach(() => {
  vi.clearAllMocks();
  mockFetchBuckets.mockResolvedValue([
    {
      meta_id: 119,
      finalized: false,
      agent_id: '005',
      agent_name: 'rbta-arya',
      rule_group_primary: 'rootcheck',
      start_time: '2026-10-04T02:50:59+00:00',
      end_time: '2026-10-04T03:39:53+00:00',
      alert_count: 111,
      max_severity: 8,
    },
  ]);
  mockFetchBucketRawAlerts.mockResolvedValue({
    meta_id: null,
    source_total: 1,
    resolved_total: 1,
    filtered_total: 1,
    unresolved_alert_ids: [],
    items: [member],
    page: 1,
    page_size: 20,
  });
});

describe('BucketDetailPage', () => {
  it('menampilkan identitas bucket + anggota raw alert', async () => {
    renderPage();
    expect(await screen.findByText(/Kelompok 005 · rootcheck/)).toBeInTheDocument();
    expect(await screen.findByText(/^masih bertambah$/i)).toBeInTheDocument();
    expect(await screen.findByText('a1')).toBeInTheDocument();
    expect(screen.getByText('Rootcheck event')).toBeInTheDocument();
  });

  it('menampilkan tautan MetaAlert bila bucket sudah final', async () => {
    const { ApiError } = await import('@/api/client');
    mockFetchBucketRawAlerts.mockRejectedValue(
      new ApiError(404, JSON.stringify({ detail: 'tutup', finalized_meta_id: 119 })),
    );
    renderPage();
    expect(await screen.findByText(/sudah ditutup menjadi meta-alert #119/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /buka meta-alert #119/i })).toBeInTheDocument();
  });

  it('menampilkan banner tanpa tautan bila bucket tak dikenal', async () => {
    const { ApiError } = await import('@/api/client');
    mockFetchBucketRawAlerts.mockRejectedValue(new ApiError(404, 'tidak ada'));
    renderPage();
    expect(await screen.findByText(/kelompok tidak lagi terbuka/i)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /buka meta-alert/i })).not.toBeInTheDocument();
  });

  it('baris anggota menuju rute detail raw alert bucket', async () => {
    renderPage();
    const row = await screen.findByText('a1');
    fireEvent.click(row.closest('tr') as HTMLElement);
    expect(await screen.findByTestId('path')).toHaveTextContent(
      '/live/buckets/005/rootcheck/raw-alerts/a1',
    );
  });
});
