import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { SidebarProvider } from '@cloudflare/kumo/components/sidebar';
import { describe, expect, it, vi } from 'vitest';
import { AppSidebar } from './Sidebar';

vi.stubGlobal('matchMedia', (query: string) => ({
  matches: false,
  media: query,
  onchange: null,
  addListener: () => {},
  removeListener: () => {},
  addEventListener: () => {},
  removeEventListener: () => {},
  dispatchEvent: () => false,
}));

function renderSidebar() {
  return render(
    <MemoryRouter initialEntries={['/overview']}>
      <SidebarProvider>
        <AppSidebar />
      </SidebarProvider>
    </MemoryRouter>,
  );
}

describe('AppSidebar live stream', () => {
  it('menampilkan entri Pemantauan live di atas Replay sidang', () => {
    renderSidebar();
    const live = screen.getByText('Pemantauan live');
    const replay = screen.getByText('Replay sidang');
    expect(live).toBeInTheDocument();
    expect(replay).toBeInTheDocument();
    expect(live.compareDocumentPosition(replay) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });
});
