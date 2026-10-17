import type { ReplayDataset } from '@/api/schemas';
import { CheckCircle, ShieldWarning } from '@phosphor-icons/react';
import { TERMS } from '@/lib/labels';

export function ResearchBoundaryCard({ dataset, modelVersion }: { dataset?: ReplayDataset; modelVersion: string }) {
  const checks = [
    ['Dataset', dataset ? `${dataset.classification} · ${dataset.total_events.toLocaleString('id-ID')} alert` : 'belum dipilih'],
    ['Integritas', dataset?.sha256 ? `${dataset.is_valid ? 'valid' : `tidak valid (${dataset.invalid_events})`} · SHA-256 ${dataset.sha256.slice(0, 12)}…` : 'manifest belum tersedia'],
    [TERMS.frozenModel, modelVersion || 'belum tersedia'],
  ];
  return (
    <section className="rounded-2xl border border-kumo-hairline bg-kumo-canvas p-6 shadow-xs" aria-labelledby="demo-boundary-title">
      <div className="grid gap-6 lg:grid-cols-[1.4fr_1fr]">
        <div>
          <div className="mb-3 flex items-center gap-2 text-amber-700 dark:text-amber-300">
            <ShieldWarning size={22} weight="duotone" />
            <h2 id="demo-boundary-title" className="text-base font-bold text-kumo-strong">Apa yang dibuktikan demo ini?</h2>
          </div>
          <p className="max-w-3xl text-sm leading-6 text-kumo-default">
            Sistem mengelompokkan alert menjadi satuan yang perlu dicek analyst, mempertahankan bukti asli, lalu memberi prioritas dengan skor keanehan. Ini <strong>bukan pendeteksi kebenaran serangan</strong> dan bukan pengukuran akurasi serangan tanpa label kebenaran (ground truth).
          </p>
          <div className="mt-4 grid gap-3 sm:grid-cols-3">
            {['RBTA: pengurangan + konteks', 'Isolation Forest: prioritas keanehan', 'Bukti asli: dapat ditelusuri'].map((item) => (
              <div key={item} className="rounded-xl bg-kumo-recessed/60 px-3 py-2 text-xs font-semibold text-kumo-strong">{item}</div>
            ))}
          </div>
        </div>
        <dl className="space-y-2 rounded-xl border border-kumo-hairline bg-kumo-recessed/30 p-4">
          {checks.map(([label, value]) => (
            <div key={label} className="flex items-start gap-2 text-xs">
              <CheckCircle className="mt-0.5 shrink-0 text-emerald-600" size={15} weight="fill" />
              <dt className="w-28 shrink-0 font-semibold text-kumo-subtle">{label}</dt>
              <dd className="break-all font-mono text-kumo-strong">{value}</dd>
            </div>
          ))}
        </dl>
      </div>
    </section>
  );
}
