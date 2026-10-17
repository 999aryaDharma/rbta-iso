import '@testing-library/jest-dom/vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { describe, expect, it, vi, beforeEach } from 'vitest';
import { LiveTriageSummaryPanel, type TriageSummaryDatum } from './LiveTriageSummary';
import { LiveTriageSummaryCard } from './LiveTriageSummary';

const { mockFetchSummary, mockFetchLiveStatus, mockFetchMetaAlerts } = vi.hoisted(() => ({
  mockFetchSummary: vi.fn(),
  mockFetchLiveStatus: vi.fn(),
  mockFetchMetaAlerts: vi.fn(),
}));

vi.mock('@/api/dashboard', () => ({ fetchSummary: mockFetchSummary }));
vi.mock('@/api/live', () => ({ fetchLiveStatus: mockFetchLiveStatus }));
vi.mock('@/api/metaAlerts', () => ({ fetchMetaAlerts: mockFetchMetaAlerts }));

const baseDatum: TriageSummaryDatum = {
  rawAlerts: 1899,
  metaAlerts: 42,
  arrPercent: 97.8,
  escalateOpen: 5,
  outboxPending: 1,
  decisionCounts: { CRITICAL: 2, SUSPICIOUS: 3, NOISE_HIGH: 7, NOISE: 30 },
  decisionSampled: 42,
  decisionTotal: 42,
  decisionUnavailable: false,
  eventLagSec: 4.2,
  stale: false,
  workerAlive: true,
};

function renderCard() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <LiveTriageSummaryCard />
    </QueryClientProvider>,
  );
}

describe('LiveTriageSummaryPanel', () => {
  it('menampilkan state loading saat memuat', () => {
    render(<LiveTriageSummaryPanel isLoading isError={false} data={null} onRetry={() => {}} />);
    expect(screen.getByRole('status')).toHaveTextContent(/memuat/i);
  });

  it('menampilkan error + tombol coba lagi', () => {
    const onRetry = vi.fn();
    render(<LiveTriageSummaryPanel isLoading={false} isError data={null} errorMessage="putus" onRetry={onRetry} />);
    expect(screen.getByRole('alert')).toHaveTextContent(/putus/);
    fireEvent.click(screen.getByRole('button', { name: /coba lagi/i }));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  it('menampilkan reduksi live: alert masuk, MetaAlert final, ARR%', () => {
    render(<LiveTriageSummaryPanel isLoading={false} isError={false} data={baseDatum} onRetry={() => {}} />);
    expect(screen.getByText('1899')).toBeInTheDocument();
    expect(screen.getByText('42')).toBeInTheDocument();
    expect(screen.getByText(/97\.8%/)).toBeInTheDocument();
  });

  it('menegaskan batas klaim: ARR reduksi triase bukan akurasi, skor prioritas bukan vonis', () => {
    render(<LiveTriageSummaryPanel isLoading={false} isError={false} data={baseDatum} onRetry={() => {}} />);
    expect(screen.getByText(/pengurangan jumlah yang perlu dicek analyst, bukan akurasi/i)).toBeInTheDocument();
    expect(screen.getByText(/prioritas.*bukan vonis serangan/i)).toBeInTheDocument();
  });

  it('menampilkan ESCALATE terbuka + outbox tanpa paragraf bocoran dapur', () => {
    render(<LiveTriageSummaryPanel isLoading={false} isError={false} data={baseDatum} onRetry={() => {}} />);
    expect(screen.getByText(/perlu dicek segera/i)).toBeInTheDocument();
    expect(screen.getByText('Antrean Telegram')).toBeInTheDocument();
    expect(screen.queryByText(/umur tertua tidak tersedia/i)).not.toBeInTheDocument();
  });

  it('menampilkan funnel reduksi sebagai satu strip', () => {
    render(<LiveTriageSummaryPanel isLoading={false} isError={false} data={baseDatum} onRetry={() => {}} />);
    expect(
      screen.getByRole('img', { name: /reduksi: 1899 alert menjadi 42 meta-alert/i }),
    ).toBeInTheDocument();
  });

  it('menampilkan distribusi level sebagai stacked bar satu warna per level', () => {
    render(<LiveTriageSummaryPanel isLoading={false} isError={false} data={baseDatum} onRetry={() => {}} />);
    expect(
      screen.getByRole('img', { name: /Kritis 2.*Mencurigakan 3.*Keparahan tinggi, pola biasa 7.*Biasa 30/i }),
    ).toBeInTheDocument();
  });

  it('menampilkan distribusi level per label', () => {
    render(<LiveTriageSummaryPanel isLoading={false} isError={false} data={baseDatum} onRetry={() => {}} />);
    expect(screen.getByText('CRITICAL')).toBeInTheDocument();
    expect(screen.getByText('SUSPICIOUS')).toBeInTheDocument();
    expect(screen.getByText('NOISE_HIGH')).toBeInTheDocument();
    expect(screen.getByText('NOISE')).toBeInTheDocument();
  });

  it('menandai basi bila lag event melewati ambang', () => {
    render(
      <LiveTriageSummaryPanel
        isLoading={false}
        isError={false}
        data={{ ...baseDatum, stale: true }}
        onRetry={() => {}}
      />,
    );
    expect(screen.getByText(/belum diperbarui lebih dari 2 menit/i)).toBeInTheDocument();
  });

  it('tidak menampilkan hitungan siklus internal', () => {
    render(<LiveTriageSummaryPanel isLoading={false} isError={false} data={baseDatum} onRetry={() => {}} />);
    expect(screen.queryByText('Siklus selesai')).not.toBeInTheDocument();
    expect(screen.queryByText(/cycles_completed/i)).not.toBeInTheDocument();
  });
});

describe('LiveTriageSummaryCard', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFetchSummary.mockResolvedValue({
      raw_alert_count: 1899,
      meta_alert_count: 42,
      alert_reduction_rate_percent: 97.8,
      escalate_count: 5,
      digest_count: 7,
      suppress_count: 30,
      anomalies_detected: 5,
      critical_meta_count: 2,
      active_buckets_count: 3,
      source_mode: 'live',
      system_status: 'ok',
    });
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
    mockFetchMetaAlerts.mockResolvedValue({
      items: [
        { decision: 'CRITICAL' },
        { decision: 'SUSPICIOUS' },
        { decision: 'NOISE' },
      ],
      total: 3,
      page: 1,
      page_size: 100,
    });
  });

  it('merakit angka reduksi dari /dashboard/summary tanpa mengubah rumus', async () => {
    renderCard();
    expect(await screen.findByText('1899')).toBeInTheDocument();
    expect(screen.getByText(/97\.8%/)).toBeInTheDocument();
    expect(mockFetchSummary).toHaveBeenCalled();
  });

  it('menampilkan distribusi level dari daftar live tanpa mengarang angka', async () => {
    renderCard();
    expect(await screen.findByText('CRITICAL')).toBeInTheDocument();
    expect(screen.getByText('SUSPICIOUS')).toBeInTheDocument();
  });
});
