import React from 'react';
import { useSearchParams } from 'react-router-dom';
import { Button } from '@cloudflare/kumo/components/button';
import { Badge } from '@cloudflare/kumo/components/badge';
import {
  MagnifyingGlass, Question, Sun, Moon, Desktop, User,
} from '@phosphor-icons/react';
import { usePollingQuery } from '@/hooks/usePolling';
import { fetchSummary } from '@/api/dashboard';
import { useTheme } from '@/context/ThemeContext';
import { ShortcutsModal } from './ShortcutsModal';
import { CommandPalette } from './CommandPalette';

export function Topbar() {
  const [searchParams] = useSearchParams();
  const runId = searchParams.get('run_id');
  const { data } = usePollingQuery(['summary-topbar', runId || 'live'], () => fetchSummary(runId || undefined), 3000);
  const { theme, setTheme } = useTheme();

  const [showShortcuts, setShowShortcuts] = React.useState(false);
  const [showPalette, setShowPalette] = React.useState(false);

  React.useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement;
      if (['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName) || target.isContentEditable) {
        return;
      }
      if (e.key === '/' || (e.key === 'k' && (e.metaKey || e.ctrlKey))) {
        e.preventDefault();
        setShowPalette(true);
      } else if (e.key === '?') {
        e.preventDefault();
        setShowShortcuts(true);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const cycleTheme = () => {
    if (theme === 'light') setTheme('dark');
    else if (theme === 'dark') setTheme('system');
    else setTheme('light');
  };

  return (
    <>
      <header className="w-full h-14 min-h-[3.5rem] flex items-center justify-between px-6 lg:px-8 border-b border-kumo-line bg-kumo-canvas shrink-0 z-20 sticky top-0">
        <div className="flex items-center gap-3 min-w-0">
          <div className="flex items-center gap-2 text-sm font-medium text-kumo-subtle">
            <span>Operasi keamanan</span>
            <span>/</span>
            <span className="text-kumo-strong font-semibold">SOC kampus</span>
          </div>

          <span className="h-4 w-px bg-kumo-line hidden sm:inline-block shrink-0" />

          <div className="flex items-center gap-2 text-xs">
            {runId ? (
              <Badge variant="warning">REPLAY: {runId.slice(0, 8)}</Badge>
            ) : (
              <Badge variant="success">DATA LANGSUNG</Badge>
            )}

            <span className="hidden lg:inline-flex">
              <Badge variant={data?.system_status === 'READY' ? 'secondary' : 'error'}>
                {data?.system_status === 'READY' ? 'SISTEM SIAP' : 'TERGANGGU'}
              </Badge>
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            type="button"
            onClick={() => setShowPalette(true)}
            className="flex items-center justify-between gap-3 px-3 py-1.5 rounded-lg border border-kumo-line bg-kumo-recessed/40 hover:bg-kumo-recessed text-kumo-subtle hover:text-kumo-default text-sm transition-colors cursor-pointer w-40 sm:w-56"
            title="Cari (tekan / atau ⌘K)"
          >
            <div className="flex items-center gap-2 truncate">
              <MagnifyingGlass size={15} className="shrink-0 text-kumo-subtle" />
              <span className="truncate">Cari…</span>
            </div>
            <kbd className="rounded border border-kumo-line bg-kumo-canvas px-1.5 py-0.5 text-xs font-mono text-kumo-subtle">
              /
            </kbd>
          </button>

          <Button
            variant="ghost"
            size="sm"
            onClick={cycleTheme}
            aria-label={`Tema: ${theme}`}
            className="text-kumo-subtle hover:text-kumo-default"
          >
            {theme === 'light' && <Sun size={17} />}
            {theme === 'dark' && <Moon size={17} />}
            {theme === 'system' && <Desktop size={17} />}
          </Button>

          <Button
            variant="ghost"
            size="sm"
            onClick={() => setShowShortcuts(true)}
            aria-label="Pintasan keyboard"
            className="text-kumo-subtle hover:text-kumo-default"
          >
            <Question size={17} />
          </Button>

          <div className="hidden sm:flex items-center gap-2.5 pl-3 ml-1 border-l border-kumo-line">
            <div className="size-8 rounded-full bg-kumo-recessed border border-kumo-line flex items-center justify-center text-kumo-strong">
              <User size={15} />
            </div>
            <div className="hidden xl:flex flex-col text-left">
              <span className="text-xs font-semibold text-kumo-strong leading-none">Analyst SOC</span>
              <span className="text-[11px] font-mono text-kumo-subtle mt-0.5">Pengguna dashboard</span>
            </div>
          </div>
        </div>
      </header>

      <ShortcutsModal open={showShortcuts} onClose={() => setShowShortcuts(false)} />
      <CommandPalette open={showPalette} onClose={() => setShowPalette(false)} />
    </>
  );
}
