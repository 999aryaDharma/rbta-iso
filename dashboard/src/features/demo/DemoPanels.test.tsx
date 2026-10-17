import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { LiveEvaluationPanel } from './LiveEvaluationPanel';
import { PostReplayEvaluation } from './PostReplayEvaluation';
import { getSilhouetteChartBounds } from './silhouetteChart';
import { ResearchBoundaryCard } from './ResearchBoundaryCard';
import { DatasetCatalogPanel } from './DatasetCatalogPanel';

const live = {
  schema_version: '1.0',
  raw_alerts: 100,
  finalized_meta_alerts: 8,
  active_meta_alerts: 2,
  triage_units_current: 10,
  live_arr_percent: 90,
  decision_distribution: { CRITICAL: 2, SUSPICIOUS: 1, NOISE_HIGH: 1, NOISE: 4 },
  action_distribution: { ESCALATE: 3, DAILY_DIGEST: 1, SUPPRESS: 4 },
  threshold: { above_count: 3, above_rate_percent: 37.5 },
  score_distribution: {
    count: 8, min: 0.1, max: 1.2, mean: 0.54,
    bins: ['<0', '0–<0.25', '0.25–<0.5', '0.5–<0.75', '0.75–1', '>1'],
    histogram: [0, 2, 2, 1, 2, 1],
  },
  reference_range_exceedance_count: 1,
  evidence_coverage_percent: 100,
  source_reference_coverage_percent: 95,
  model_provenance: { model_version: 'rbta-if-v1', training_run_id: 'train-001' },
  claim_boundary: {
    accuracy_available: false,
    arr_interpretation: 'ARR mengukur pengurangan unit triase, bukan akurasi deteksi serangan.',
    score_interpretation: 'Isolation Forest memberi skor keanehan untuk prioritas, bukan label serangan.',
    silhouette_interpretation: 'Silhouette adalah evaluasi struktural internal, bukan bukti akurasi serangan.',
    contamination_interpretation: "contamination='auto' tidak menentukan eskalasi.",
  },
};

class ResizeObserverMock {
  observe() {}
  unobserve() {}
  disconnect() {}
}

vi.stubGlobal('ResizeObserver', ResizeObserverMock);

describe('thesis Demo explanation panels', () => {
  it('keeps the silhouette bars and reference markers inside padded chart bounds', () => {
    const bounds = getSilhouetteChartBounds([
      { x: -0.003, count: 45 },
      { x: 0.031, count: 1 },
    ], 0.042, 0.001);

    expect(bounds.xDomain[0]).toBeLessThan(-0.003);
    expect(bounds.xDomain[1]).toBeGreaterThan(0.042);
    expect(bounds.yDomain).toEqual([0, 50]);
  });

  it('explains dataset indexing and sidecar exclusion', () => {
    render(<DatasetCatalogPanel status={{
      status: 'RUNNING', total_files: 142, completed_files: 38, failed_files: 0, invalid_files: 0,
      pending_files: 104, current_file: 'wazuh-alerts-4.x-2026.05.10.jsonl', last_error: null,
      errors: [], started_at_utc: null, completed_at_utc: null,
    }} onRefresh={vi.fn()} disabled={false} />);
    expect(screen.getByText(/38 dari 142/i)).toBeInTheDocument();
    expect(screen.getByText((_, element) => element?.tagName === 'P' && Boolean(element.textContent?.includes('.meta tidak dibaca sebagai alert')))).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /indeks ulang/i })).toBeDisabled();
  });
  it('explains live metrics and their limits', () => {
    render(<LiveEvaluationPanel live={live} eventsPerSecond={1250} />);
    expect(screen.getByText('90.00%')).toBeInTheDocument();
    expect(screen.getByText(/pengurangan unit triase, bukan akurasi/i)).toBeInTheDocument();
    expect(screen.getByText(/di luar rentang referensi/i)).toBeInTheDocument();
  });

  it('states the research claim boundary and frozen provenance', () => {
    render(
      <ResearchBoundaryCard
        dataset={{ name: 'golden.jsonl.gz', size_bytes: 100, total_events: 5000, valid_events: 5000, invalid_events: 0, is_valid: true, sha256: 'a'.repeat(64), compression: 'gzip', classification: 'golden', inspection_status: 'cached' }}
        modelVersion="rbta-if-v1"
      />
    );
    expect(screen.getByText(/apa yang dibuktikan demo ini/i)).toBeInTheDocument();
    expect(screen.getByText(/bukan pendeteksi kebenaran serangan/i)).toBeInTheDocument();
    expect(screen.getByText(/golden/i)).toBeInTheDocument();
    expect(screen.getByText(/aaaaaaaaaaaa/i)).toBeInTheDocument();
  });

  it('renders complete evaluation progress and interpretation boundary', () => {
    render(
      <PostReplayEvaluation
        replayStatus="COMPLETED"
        evaluation={{
          run_id: 'run-1', status: 'COMPLETED', current_phase: 'completed',
          completed_phases: 7, total_phases: 7, progress_percent: 100,
          artifact_available: true, last_error: null,
          results: {
            aggregation_ablation: [
              { variant: 'time_only_fixed', n_raw: 100, n_meta: 5, arr: 95, context_purity_percent: 40, context_contamination_percent: 60 },
              { variant: 'contextual_fixed', n_raw: 100, n_meta: 10, arr: 90, context_purity_percent: 100, context_contamination_percent: 0 },
              { variant: 'contextual_adaptive', n_raw: 100, n_meta: 8, arr: 92, context_purity_percent: 100, context_contamination_percent: 0 },
            ],
            structural_silhouette: { is_calculable: true, observed_silhouette: 0.42, random_mean: 0.01, empirical_p_value: 0.0198, n_valid_permutations: 100, null_histogram: { bin_edges: [-0.04, -0.02, 0, 0.02, 0.04], counts: [3, 17, 42, 38] } },
          },
        }}
        onStart={vi.fn()}
        onCancel={vi.fn()}
        onDownload={vi.fn()}
      />
    );
    expect(screen.getByText(/evaluasi lengkap rbta/i)).toBeInTheDocument();
    expect(screen.getByText(/hanya waktu, jendela tetap/i)).toBeInTheDocument();
    expect(screen.getByText(/pemisahan kelompok secara internal/i)).toBeInTheDocument();
    expect(screen.getByRole('img', { name: /histogram pembanding acak silhouette/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /unduh hasil/i })).toBeInTheDocument();
  });

  it('uses plain-language labels and keeps the score distribution readable without color alone', () => {
    render(<LiveEvaluationPanel live={live} eventsPerSecond={1250} />);
    expect(screen.getByText(/hasil sementara saat replay berjalan/i)).toBeInTheDocument();
    expect(screen.getByRole('table', { name: /angka distribusi skor model/i })).toBeInTheDocument();
  });
});
