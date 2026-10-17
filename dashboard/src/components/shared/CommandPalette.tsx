import * as React from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { DialogRoot, Dialog, DialogClose } from '@cloudflare/kumo/components/dialog';
import { Button } from '@cloudflare/kumo/components/button';
import {
  ChartBar, PaintBucket, Cpu, Play, Plugs, GearSix, ArrowRight, MagnifyingGlass, Hash, Pulse,
} from '@phosphor-icons/react';

export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [query, setQuery] = React.useState('');
  const [selectedIndex, setSelectedIndex] = React.useState(0);
  const runId = searchParams.get('run_id');

  const withRunId = (path: string) =>
    runId ? `${path}${path.includes('?') ? '&' : '?'}run_id=${encodeURIComponent(runId)}` : path;

  const navItems = [
    { label: 'Ringkasan', category: 'Halaman', desc: 'Kondisi alert dan beban analyst saat ini', path: withRunId('/overview'), icon: ChartBar },
    { label: 'Daftar meta-alert', category: 'Halaman', desc: 'Telusuri kelompok alert dan skornya', path: withRunId('/meta-alerts'), icon: PaintBucket },
    { label: 'Status pengelompokan', category: 'Halaman', desc: 'Kelompok terbuka dan jendela waktu per agen', path: withRunId('/rbta'), icon: Cpu },
    { label: 'Pemantauan live', category: 'Halaman', desc: 'Status pemrosesan dan kesegaran data', path: withRunId('/live'), icon: Pulse },
    { label: 'Replay sidang', category: 'Halaman', desc: 'Putar ulang data penelitian dan hasil evaluasi', path: withRunId('/demo'), icon: Play },
    { label: 'Integrasi', category: 'Operasi', desc: 'Status Telegram dan Shuffle', path: withRunId('/integrations'), icon: Plugs },
    { label: 'Sistem', category: 'Operasi', desc: 'Versi model dan konfigurasi', path: withRunId('/system'), icon: GearSix },
  ];

  const isNumericId = /^#?(\d+)$/.test(query.trim());
  const numericId = query.trim().replace(/^#/, '');

  const filteredItems = navItems.filter((i) =>
    i.label.toLowerCase().includes(query.toLowerCase()) ||
    i.desc.toLowerCase().includes(query.toLowerCase())
  );

  React.useEffect(() => {
    setSelectedIndex(0);
  }, [query]);

  const handleSelect = (path: string) => {
    navigate(path);
    setQuery('');
    onClose();
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex((prev) => (prev + 1) % (filteredItems.length + (isNumericId ? 1 : 0)));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      const total = filteredItems.length + (isNumericId ? 1 : 0);
      setSelectedIndex((prev) => (prev - 1 + total) % total);
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (isNumericId) {
        navigate(withRunId(`/meta-alerts/${numericId}`));
        setQuery('');
        onClose();
      } else if (filteredItems[selectedIndex]) {
        handleSelect(filteredItems[selectedIndex].path);
      }
    }
  };

  return (
    <DialogRoot open={open} onOpenChange={(o) => { if (!o) { setQuery(''); onClose(); } }}>
      <Dialog className="max-w-xl w-full p-0 bg-kumo-canvas border border-kumo-hairline shadow-2xl rounded-xl overflow-hidden">
        <div className="flex items-center gap-3 px-5 py-4 border-b border-kumo-hairline bg-kumo-canvas">
          <MagnifyingGlass size={18} className="text-kumo-strong shrink-0" />
          <input
            autoFocus
            type="text"
            placeholder="Cari halaman atau ketik nomor meta-alert (mis. 42)…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            className="w-full bg-transparent text-sm text-kumo-strong placeholder:text-kumo-subtle focus:outline-hidden font-normal"
          />
          {query && (
            <button
              onClick={() => setQuery('')}
              className="text-xs text-kumo-subtle hover:text-kumo-strong px-1.5 py-0.5 rounded cursor-pointer"
            >
              Hapus
            </button>
          )}
        </div>

        <div className="p-3 max-h-[360px] overflow-y-auto space-y-1.5">
          {isNumericId && (
            <button
              onClick={() => {
                navigate(withRunId(`/meta-alerts/${numericId}`));
                setQuery('');
                onClose();
              }}
              className="w-full flex items-center justify-between rounded-lg p-3 text-sm text-left transition-colors bg-kumo-recessed border border-kumo-hairline text-kumo-strong cursor-pointer"
            >
              <div className="flex items-center gap-3">
                <div className="w-7 h-7 rounded-md bg-kumo-canvas border border-kumo-hairline text-kumo-strong flex items-center justify-center">
                  <Hash size={14} weight="bold" />
                </div>
                <div>
                  <div className="font-semibold text-xs text-kumo-strong">
                    Langsung ke meta-alert #{numericId}
                  </div>
                  <div className="text-[11px] text-kumo-subtle">
                    Buka detail meta-alert nomor {numericId}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-1 text-xs text-kumo-strong font-medium">
                <span>Buka</span>
                <ArrowRight size={13} />
              </div>
            </button>
          )}

          {filteredItems.map((item, idx) => {
            const Icon = item.icon;
            const isSelected = idx === selectedIndex && !isNumericId;
            return (
              <button
                key={item.path}
                onClick={() => handleSelect(item.path)}
                onMouseEnter={() => setSelectedIndex(idx)}
                className={`w-full flex items-center justify-between rounded-lg p-3 text-sm text-left transition-colors cursor-pointer ${
                  isSelected
                    ? 'bg-kumo-recessed text-kumo-strong border border-kumo-hairline shadow-2xs font-medium'
                    : 'hover:bg-kumo-recessed/60 text-kumo-default border border-transparent'
                }`}
              >
                <div className="flex items-center gap-3">
                  <div className="w-7 h-7 rounded-md bg-kumo-canvas border border-kumo-hairline flex items-center justify-center text-kumo-strong shrink-0">
                    <Icon size={16} />
                  </div>
                  <div>
                    <div className="font-medium text-xs text-kumo-strong flex items-center gap-2">
                      <span>{item.label}</span>
                      <span className="text-[10px] uppercase font-semibold text-kumo-subtle tracking-wider px-1.5 py-0.2 rounded bg-kumo-canvas border border-kumo-hairline">
                        {item.category}
                      </span>
                    </div>
                    <div className="text-[11px] text-kumo-subtle mt-0.5">
                      {item.desc}
                    </div>
                  </div>
                </div>
                <ArrowRight
                  size={14}
                  className={isSelected ? 'text-kumo-strong' : 'text-kumo-subtle'}
                />
              </button>
            );
          })}

          {filteredItems.length === 0 && !isNumericId && (
            <div className="py-8 text-center text-xs text-kumo-subtle space-y-1">
              <p className="font-medium text-kumo-default">Tidak ada hasil</p>
              <p>Ketik nomor seperti <span className="font-mono text-kumo-strong font-semibold">42</span> untuk langsung ke meta-alert tertentu</p>
            </div>
          )}
        </div>

        <div className="px-5 py-3 border-t border-kumo-hairline bg-kumo-recessed/40 flex items-center justify-between text-[11px] text-kumo-subtle">
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-1.5">
              <kbd className="px-1.5 py-0.5 rounded border border-kumo-hairline bg-kumo-canvas font-mono text-[10px]">↑↓</kbd>
              Navigasi
            </span>
            <span className="flex items-center gap-1.5">
              <kbd className="px-1.5 py-0.5 rounded border border-kumo-hairline bg-kumo-canvas font-mono text-[10px]">↵</kbd>
              Pilih
            </span>
            <span className="flex items-center gap-1.5">
              <kbd className="px-1.5 py-0.5 rounded border border-kumo-hairline bg-kumo-canvas font-mono text-[10px]">ESC</kbd>
              Tutup
            </span>
          </div>
          <DialogClose>
            <Button variant="ghost" size="sm" className="h-6 text-[11px]">
              Tutup
            </Button>
          </DialogClose>
        </div>
      </Dialog>
    </DialogRoot>
  );
}
