import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { DecisionBadge } from './DecisionBadge';
import { ACTION_LABELS, DECISION_LABELS, FEATURE_LABELS } from '@/lib/labels';

describe('DecisionBadge', () => {
  it('menampilkan label Indonesia dengan kode asli sebagai teks sekunder', () => {
    render(<DecisionBadge decision="NOISE_HIGH" action="DAILY_DIGEST" />);
    expect(screen.getByText(/Keparahan tinggi, pola biasa/)).toBeInTheDocument();
    expect(screen.getByText('NOISE_HIGH')).toBeInTheDocument();
    expect(screen.getByText(/Ringkasan harian/)).toBeInTheDocument();
    expect(screen.getByText('DAILY_DIGEST')).toBeInTheDocument();
  });

  it('jatuh ke kode mentah bila nilai tidak dikenal', () => {
    render(<DecisionBadge decision="BARU" action="ENTAH" />);
    expect(screen.getByText(/Level: BARU/)).toBeInTheDocument();
    expect(screen.getByText(/Aksi: ENTAH/)).toBeInTheDocument();
  });

  it('kamus mencakup semua kode backend', () => {
    expect(Object.keys(DECISION_LABELS)).toEqual(['CRITICAL', 'SUSPICIOUS', 'NOISE_HIGH', 'NOISE', 'CONTEXTUAL_ANOMALY']);
    expect(Object.keys(ACTION_LABELS)).toEqual(['ESCALATE', 'DAILY_DIGEST', 'SUPPRESS']);
    expect(Object.keys(FEATURE_LABELS)).toHaveLength(7);
  });
});
