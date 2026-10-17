import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { describe, expect, it, vi, beforeEach } from 'vitest';
import { LiveTransportDetails } from './LiveTransportDetails';

const { mockFetchLiveStatus } = vi.hoisted(() => ({
  mockFetchLiveStatus: vi.fn(),
}));

vi.mock('@/api/live', () => ({ fetchLiveStatus: mockFetchLiveStatus }));

function renderDetails() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <LiveTransportDetails />
    </QueryClientProvider>,
  );
}

describe('LiveTransportDetails', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFetchLiveStatus.mockResolvedValue({
      worker_alive: true,
      cycles_completed: 12,
      consecutive_failures: 0,
      last_error: null,
      last_cycle_at: new Date().toISOString(),
      live_model_version: 'rbta-if-v1',
      recent_poll_cursor: null,
      lag_sec: 4.2,
      buffer_size: null,
      buffer_stats: null,
      outbox_pending: 1,
      ingested_total: 1899,
      dispatcher: null,
      quarantine_total: 0,
      newest_scored_event_time: null,
      newest_ingested_event_time: new Date().toISOString(),
      event_lag_sec: 4.2,
      tls_verify: true,
    });
  });

  it('merender blok sekunder collapsible di bawah timeline', () => {
    renderDetails();
    expect(screen.getByText(/detail teknis koneksi/i)).toBeInTheDocument();
    expect(document.querySelector('details')).toBeInTheDocument();
  });

  it('memuat metrik transport worker di dalam blok sekunder', async () => {
    renderDetails();
    expect(await screen.findByText(/pemrosesan berjalan/i)).toBeInTheDocument();
  });

  it('tidak menampilkan hitungan siklus internal', async () => {
    renderDetails();
    await screen.findByText(/pemrosesan berjalan/i);
    expect(screen.queryByText('Siklus selesai')).not.toBeInTheDocument();
  });
});
