import { DialogRoot, Dialog, DialogTitle, DialogClose } from '@cloudflare/kumo/components/dialog';
import { Button } from '@cloudflare/kumo/components/button';
import { Keyboard } from '@phosphor-icons/react';

export function ShortcutsModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const shortcutGroups = [
    {
      category: 'NAVIGASI',
      items: [
        { key: 'g o', desc: 'Buka Ringkasan' },
        { key: 'g m', desc: 'Buka Daftar meta-alert' },
        { key: 'g r', desc: 'Buka Status pengelompokan' },
        { key: 'g d', desc: 'Buka Replay sidang' },
        { key: 'g l', desc: 'Buka Pemantauan live' },
        { key: 'g s', desc: 'Buka Sistem' },
      ],
    },
    {
      category: 'PENCARIAN & PINTASAN',
      items: [
        { key: '/', desc: 'Buka pencarian cepat' },
        { key: '⌘ K', desc: 'Buka pencarian cepat' },
        { key: '?', desc: 'Tampilkan/sembunyikan daftar pintasan' },
      ],
    },
    {
      category: 'PEMERIKSAAN',
      items: [
        { key: '[', desc: 'Alert sebelumnya dalam meta-alert' },
        { key: ']', desc: 'Alert berikutnya dalam meta-alert' },
      ],
    },
  ];

  return (
    <DialogRoot open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <Dialog className="max-w-md w-full p-6 bg-kumo-canvas border border-kumo-hairline shadow-2xl rounded-xl">
        <div className="flex items-center gap-3 pb-3 border-b border-kumo-hairline">
          <div className="w-8 h-8 rounded-lg bg-kumo-recessed border border-kumo-hairline flex items-center justify-center text-kumo-strong">
            <Keyboard size={18} weight="duotone" />
          </div>
          <div>
            <DialogTitle className="text-base font-bold text-kumo-strong leading-none">
              Pintasan keyboard
            </DialogTitle>
            <p className="text-xs text-kumo-subtle mt-1">
              Tekan tombol berurutan, mis. g lalu o
            </p>
          </div>
        </div>

        <div className="space-y-4 my-4 max-h-[60vh] overflow-y-auto pr-1">
          {shortcutGroups.map((group) => (
            <div key={group.category} className="space-y-1.5">
              <span className="text-[10px] font-semibold text-kumo-subtle uppercase tracking-wider block px-1">
                {group.category}
              </span>
              <div className="rounded-lg border border-kumo-hairline bg-kumo-recessed/40 divide-y divide-kumo-hairline/60">
                {group.items.map((s) => (
                  <div
                    key={s.key}
                    className="flex items-center justify-between px-3 py-2 text-xs"
                  >
                    <span className="text-kumo-default">{s.desc}</span>
                    <kbd className="px-2 py-0.5 rounded border border-kumo-line font-mono text-[11px] font-medium bg-kumo-canvas shadow-2xs text-kumo-strong">
                      {s.key}
                    </kbd>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>

        <div className="pt-3 border-t border-kumo-hairline flex items-center justify-between">
          <span className="text-[11px] text-kumo-subtle font-mono">
            RBTA v1.0 • Pintasan aktif
          </span>
          <DialogClose>
            <Button variant="secondary" size="sm">
              Selesai
            </Button>
          </DialogClose>
        </div>
      </Dialog>
    </DialogRoot>
  );
}
