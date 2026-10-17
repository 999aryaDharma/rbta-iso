import type { LiveEvaluation } from '@/api/schemas';
import { formatNumber } from '@/lib/formatters';
import { TERMS, decisionLabel } from '@/lib/labels';

function Stat({ label, value, help }: { label: string; value: string; help: string }) {
  return <div className="rounded-xl border border-kumo-hairline bg-kumo-canvas p-4"><div className="text-[11px] font-semibold uppercase tracking-wider text-kumo-subtle">{label}</div><div className="mt-1 text-2xl font-bold text-kumo-strong">{value}</div><p className="mt-1 text-xs leading-5 text-kumo-subtle">{help}</p></div>;
}

export function LiveEvaluationPanel({ live, eventsPerSecond }: { live?: LiveEvaluation; eventsPerSecond: number }) {
  if (!live) return null;
  const maxBin = Math.max(1, ...live.score_distribution.histogram);
  return (
    <section className="space-y-4" aria-labelledby="live-evaluation-title">
      <div><h2 id="live-evaluation-title" className="text-lg font-bold text-kumo-strong">Hasil sementara saat replay berjalan</h2><p className="text-sm text-kumo-subtle">Angka diperbarui saat data diproses. Model yang dipakai tetap sama dan tidak dilatih ulang.</p></div>
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Stat label="ARR sementara" value={`${live.live_arr_percent.toFixed(2)}%`} help={live.claim_boundary.arr_interpretation} />
        <Stat label={TERMS.triageUnits} value={formatNumber(live.triage_units_current)} help={`${formatNumber(live.raw_alerts)} alert masuk → meta-alert aktif + selesai`} />
        <Stat label="Kecepatan proses" value={`${formatNumber(eventsPerSecond)} alert/detik`} help="Kecepatan pemrosesan pada komputer demo." />
        <Stat label="Bukti asli tersimpan" value={`${live.evidence_coverage_percent.toFixed(2)}%`} help="Bagian alert yang tersimpan sebagai bukti asli." />
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <div className="rounded-xl border border-kumo-hairline bg-kumo-canvas p-5">
          <h3 className="text-sm font-bold text-kumo-strong">Sebaran skor</h3>
          <p className="mt-1 text-xs text-kumo-subtle">Skor dapat berada di luar 0–1. Itu bukan kesalahan; nilai asli tetap dipakai.</p>
          <div className="mt-5 flex h-28 items-end gap-2" aria-label="Grafik sebaran skor model">
            {live.score_distribution.histogram.map((value, index) => <div key={live.score_distribution.bins[index]} className="flex flex-1 flex-col items-center gap-2"><span className="text-[10px] font-mono text-kumo-subtle">{value}</span><div className="w-full rounded-t bg-kumo-brand/80" style={{ height: `${Math.max(3, value / maxBin * 72)}px` }} /><span className="text-[9px] text-kumo-subtle">{live.score_distribution.bins[index]}</span></div>)}
          </div>
          <table className="sr-only" aria-label="Angka distribusi skor model"><thead><tr><th>Rentang skor</th><th>Jumlah</th></tr></thead><tbody>{live.score_distribution.histogram.map((value, index) => <tr key={live.score_distribution.bins[index]}><td>{live.score_distribution.bins[index]}</td><td>{value}</td></tr>)}</tbody></table>
          {live.reference_range_exceedance_count > 0 && <p className="mt-4 rounded-lg bg-amber-500/10 px-3 py-2 text-xs text-amber-800 dark:text-amber-200">{live.reference_range_exceedance_count} skor di luar rentang referensi 0–1; nilai asli dipertahankan agar auditabel.</p>}
        </div>
        <div className="rounded-xl border border-kumo-hairline bg-kumo-canvas p-5">
          <h3 className="text-sm font-bold text-kumo-strong">Hasil prioritas</h3>
          <div className="mt-4 space-y-3">{Object.entries(live.decision_distribution).map(([name, value]) => { const total = Math.max(1, live.finalized_meta_alerts); return <div key={name}><div className="mb-1 flex justify-between text-xs"><span className="font-semibold text-kumo-default" title={decisionLabel(name)?.hint}>{decisionLabel(name)?.label ?? name}{decisionLabel(name) && <span className="ml-1 font-mono text-[10px] font-normal opacity-60">{name}</span>}</span><span className="font-mono text-kumo-subtle">{value}</span></div><div className="h-2 overflow-hidden rounded-full bg-kumo-recessed"><div className="h-full rounded-full bg-kumo-brand" style={{ width: `${value / total * 100}%` }} /></div></div>; })}</div>
          <p className="mt-4 border-t border-kumo-hairline pt-3 text-xs leading-5 text-kumo-subtle">{live.claim_boundary.score_interpretation}</p>
        </div>
      </div>
    </section>
  );
}
