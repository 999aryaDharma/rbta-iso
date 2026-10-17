import '@testing-library/jest-dom/vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi, beforeEach } from 'vitest';
import { ReviewQueuePage } from './ReviewQueuePage';
import { AnalystVerdictPanel } from '@/features/meta-alerts/AnalystVerdictPanel';

const { mockFetchReviewQueue, mockPostVerdict } = vi.hoisted(() => ({
  mockFetchReviewQueue: vi.fn(),
  mockPostVerdict: vi.fn(),
}));

vi.mock('@/api/review', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/api/review')>()),
  fetchReviewQueue: mockFetchReviewQueue,
  postMetaAlertVerdict: mockPostVerdict,
}));

function wrap(ui: React.ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const item = {
  date: '2026-10-16', meta_id: 61, agent_id: '001', agent_name: 'web-1', rule_group_primary: 'pam',
  decision: 'CRITICAL', action: 'ESCALATE', anomaly_score: 0.91, alert_count: 4,
  end_time: '2026-10-15T18:00:00+00:00', queue_reason: 'ESCALATE' as const, verdict: null,
};

describe('ReviewQueuePage', () => {
  beforeEach(() => vi.clearAllMocks());

  it('menampilkan item dengan status belum/sudah dilabel', async () => {
    mockFetchReviewQueue.mockResolvedValue({
      items: [
        item,
        { ...item, meta_id: 7, action: 'SUPPRESS', decision: 'NOISE', queue_reason: 'SAMPLE_SUPPRESS',
          verdict: { meta_id: 7, verdict: 'noise', note: '', labeled_by: '', labeled_at: '2026-10-16T01:00:00Z' } },
      ],
      summary: [], sample_rate: 0.05, days: ['2026-10-16'],
    });
    wrap(<ReviewQueuePage />);
    expect(await screen.findByText('#61')).toBeInTheDocument();
    expect(screen.getByText('Belum dilabel')).toBeInTheDocument();
    expect(screen.getByText('Sampel SUPPRESS')).toBeInTheDocument();
    expect(screen.getByText(/1 dari 2 item sudah dilabel/)).toBeInTheDocument();
  });

  it('menampilkan state kosong', async () => {
    mockFetchReviewQueue.mockResolvedValue({ items: [], summary: [], sample_rate: 0.05, days: [] });
    wrap(<ReviewQueuePage />);
    expect(await screen.findByText(/belum ada metaalert live/i)).toBeInTheDocument();
  });
});

describe('AnalystVerdictPanel', () => {
  it('mengirim verdict beserta catatan', async () => {
    mockPostVerdict.mockResolvedValue({ meta_id: 61, verdict: 'incident', note: 'bf', labeled_by: '', labeled_at: '2026-10-16T01:00:00Z' });
    wrap(<AnalystVerdictPanel metaId={61} current={null} />);
    expect(screen.getByText(/belum dilabel/i)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/catatan/i), { target: { value: 'bf' } });
    fireEvent.click(screen.getByRole('button', { name: 'Insiden' }));
    await waitFor(() => expect(mockPostVerdict).toHaveBeenCalledWith(61, { verdict: 'incident', note: 'bf' }));
    expect(await screen.findByRole('button', { name: 'Insiden', pressed: true })).toBeInTheDocument();
  });
});
