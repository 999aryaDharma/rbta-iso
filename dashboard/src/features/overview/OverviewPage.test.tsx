import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it, vi, beforeEach } from 'vitest';
import { OverviewPage } from './OverviewPage';

const { mockFetchSummary, mockFetchTimeseries, mockFetchMetaAlerts } = vi.hoisted(() => ({
  mockFetchSummary: vi.fn(),
  mockFetchTimeseries: vi.fn(),
  mockFetchMetaAlerts: vi.fn(),
}));

vi.mock('@/api/dashboard', () => ({
  fetchSummary: mockFetchSummary,
  fetchTimeseries: mockFetchTimeseries,
}));

vi.mock('@/api/metaAlerts', () => ({
  fetchMetaAlerts: mockFetchMetaAlerts,
}));

const summary = {
  raw_alert_count: 1000,
  meta_alert_count: 100,
  alert_reduction_rate_percent: 90,
  escalate_count: 5,
  anomalies_detected: 7,
  active_buckets_count: 3,
  digest_count: 20,
  suppress_count: 75,
};

function renderAt(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/" element={<OverviewPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  mockFetchSummary.mockResolvedValue(summary);
  mockFetchTimeseries.mockResolvedValue([]);
  mockFetchMetaAlerts.mockResolvedValue({ items: [], total: 0 });
});

describe('OverviewPage kosakata Replay-vs-Live', () => {
  it('mode Live: judul dan deskripsi memakai kosakata arus langsung', async () => {
    renderAt('/');
    expect(await screen.findByRole('heading', { name: /ringkasan live/i })).toBeInTheDocument();
    expect(screen.getAllByText(/data langsung/i).length).toBeGreaterThan(0);
    expect(screen.queryByText(/ringkasan replay/i)).not.toBeInTheDocument();
  });

  it('mode Live: definisi metrik konsisten (ARR = reduksi triase, ESCALATE terbuka bukan vonis)', async () => {
    renderAt('/');
    await screen.findByRole('heading', { name: /ringkasan live/i });
    expect(screen.getAllByText(/pengurangan jumlah yang perlu dicek analyst, bukan akurasi/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/prioritas, bukan insiden terbukti/i)).toBeInTheDocument();
    expect(screen.getByText(/bukan label aman/i)).toBeInTheDocument();
  });

  it('mode Live: batas klaim tesis eksplisit (skor = prioritas, bukan vonis serangan)', async () => {
    renderAt('/');
    await screen.findByRole('heading', { name: /ringkasan live/i });
    expect(screen.getAllByText(/skor.*prioritas.*bukan vonis serangan/i).length).toBeGreaterThan(0);
  });

  it('mode Replay: judul menyebut Replay + run_id dan bucket terikat run replay', async () => {
    renderAt('/?run_id=run-abc-123');
    expect(await screen.findByRole('heading', { name: /ringkasan replay/i })).toBeInTheDocument();
    expect(screen.getAllByText(/run-abc-123/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/data historis/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/per agen, sesi replay ini/i)).toBeInTheDocument();
  });

  it('mode Replay: batas klaim dan definisi ARR tetap eksplisit', async () => {
    renderAt('/?run_id=run-abc-123');
    await screen.findByRole('heading', { name: /ringkasan replay/i });
    expect(screen.getAllByText(/pengurangan jumlah yang perlu dicek analyst, bukan akurasi/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/skor.*prioritas.*bukan vonis serangan/i).length).toBeGreaterThan(0);
  });
});
