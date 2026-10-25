import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { BreadcrumbContext, type Crumb } from './BreadcrumbContext';
import { Topbar } from './Topbar';

vi.mock('@/hooks/usePolling', () => ({ usePollingQuery: () => ({ data: undefined }) }));
vi.mock('@/context/ThemeContext', () => ({ useTheme: () => ({ theme: 'light', setTheme: () => {} }) }));

function renderTopbar(crumbs: Crumb[], url = '/meta-alerts/7/raw-alerts') {
  return render(
    <MemoryRouter initialEntries={[url]}>
      <BreadcrumbContext.Provider value={{ crumbs, setCrumbs: () => {} }}>
        <Topbar />
      </BreadcrumbContext.Provider>
    </MemoryRouter>,
  );
}

describe('Topbar breadcrumbs', () => {
  const crumbs: Crumb[] = [
    'Analisis',
    { label: 'Daftar meta-alert', href: '/meta-alerts' },
    { label: '#7', href: '/meta-alerts/7' },
    'Alert asli',
  ];

  it('merender crumb ber-href sebagai link, grup sebagai teks, dan terakhir sebagai halaman aktif', () => {
    renderTopbar(crumbs);
    // Kumo merender trail mobile dan desktop sekaligus; jsdom tidak menerapkan CSS.
    for (const link of screen.getAllByRole('link', { name: '#7' })) {
      expect(link).toHaveAttribute('href', '/meta-alerts/7');
    }
    expect(screen.getAllByRole('link', { name: 'Daftar meta-alert' })[0]).toHaveAttribute('href', '/meta-alerts');
    expect(screen.queryByRole('link', { name: 'Analisis' })).toBeNull();
    for (const current of screen.getAllByText('Alert asli')) {
      expect(current.closest('[aria-current="page"]')).not.toBeNull();
    }
  });

  it('membawa run_id replay ke link breadcrumb', () => {
    renderTopbar(crumbs, '/meta-alerts/7/raw-alerts?run_id=abc');
    expect(screen.getAllByRole('link', { name: '#7' })[0]).toHaveAttribute('href', '/meta-alerts/7?run_id=abc');
  });
});
