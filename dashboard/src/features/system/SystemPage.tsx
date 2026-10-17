import { usePollingQuery } from '@/hooks/usePolling';
import { fetchSystemInfo, fetchSummary } from '@/api/dashboard';
import { PageHeader } from '@/components/shared/PageHeader';
import { MetricCard } from '@/components/shared/MetricCard';
import { LiveStatusCard } from '@/features/live/LiveStatusPanel';
import { useSearchParams } from 'react-router-dom';
import { HardDrives, Cpu } from '@phosphor-icons/react';
import { Hint } from '@/components/shared/Hint';
import { FEATURE_LABELS, TERMS, TERM_HINTS } from '@/lib/labels';

export function SystemPage() {
  const [searchParams] = useSearchParams();
  const runId = searchParams.get('run_id');

  const { data: sys } = usePollingQuery(['system', runId || 'live'], () => fetchSystemInfo(runId || undefined), 3000);
  const { data: summary } = usePollingQuery(['summary', runId || 'live'], () => fetchSummary(runId || undefined), 3000);

  return (
    <>
      <PageHeader
        breadcrumbs={['Operasi', 'Sistem']}
        title="Sistem"
        description="Versi model, parameter, dan konfigurasi yang sedang berjalan"
      />

      <div className="px-6 py-8 lg:px-10 space-y-8">
        <LiveStatusCard />
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-5">
          <MetricCard label="Status sistem" value={sys?.system_status ?? '-'} sub="Dari server" />
          <MetricCard label={TERMS.modelVersion} value={sys?.model_version ?? '-'} sub={TERMS.frozenModel} />
          <MetricCard label={TERMS.threshold} value={sys ? sys.tukey_threshold.toFixed(4) : '-'} sub="Batas skor keanehan (Tukey IQR)" />
          <MetricCard label={`${TERMS.baseDeltaT} (Δt)`} value={sys ? `${sys.base_delta_t_seconds}s` : '-'} sub="Jendela awal pengelompokan" />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="p-6 rounded-xl border border-kumo-hairline bg-kumo-canvas shadow-xs space-y-4">
            <div className="flex items-center gap-3 pb-3 border-b border-kumo-hairline">
              <div className="w-8 h-8 rounded-lg border border-kumo-hairline bg-kumo-recessed text-kumo-strong flex items-center justify-center">
                <Cpu size={18} />
              </div>
              <h3 className="font-semibold text-xs uppercase tracking-wider text-kumo-strong">
                Model Isolation Forest aktif<Hint text={TERM_HINTS.IF} />
              </h3>
            </div>
            <dl className="space-y-3 text-xs">
              <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                <dt className="text-kumo-subtle font-medium">{TERMS.modelVersion}</dt>
                <dd className="font-mono font-semibold text-kumo-strong">{sys?.model_version ?? '-'}</dd>
              </div>
              <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                <dt className="text-kumo-subtle font-medium">{TERMS.threshold} (Tukey IQR)</dt>
                <dd className="font-mono font-bold text-kumo-strong">
                  {sys ? sys.tukey_threshold.toFixed(4) : '-'}
                </dd>
              </div>
              <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                <dt className="text-kumo-subtle font-medium">Seed acak (random_state)</dt>
                <dd className="font-mono text-kumo-default">{sys?.random_state ?? 'None'}</dd>
              </div>
              <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                <dt className="text-kumo-subtle font-medium">Jendela waktu adaptif<Hint text={TERM_HINTS.RBTA} /></dt>
                <dd className="font-mono font-semibold text-kumo-default">{sys?.adaptive ? 'Aktif' : 'Nonaktif'}</dd>
              </div>
              <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                <dt className="text-kumo-subtle font-medium">Aturan keputusan (skor × tingkat keparahan)</dt>
                <dd className="font-mono text-kumo-default">Matriks 4 kuadran</dd>
              </div>
              <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                <dt className="text-kumo-subtle font-medium">Penyeragaman skala fitur</dt>
                <dd className="font-mono text-kumo-default">RobustScaler (median / IQR)</dd>
              </div>
              <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                <dt className="text-kumo-subtle font-medium">Penyesuaian skor ke rentang 0–1</dt>
                <dd className="font-mono text-kumo-default">Min–max (minmax-v1)</dd>
              </div>
              <div className="pt-1">
                <dt className="text-kumo-subtle font-medium mb-1.5">7 fitur penilaian</dt>
                <dd className="font-mono text-[11px] p-3.5 rounded-lg border border-kumo-hairline bg-kumo-recessed/30 text-kumo-default leading-relaxed">
                  {(sys?.feature_names && sys.feature_names.length > 0 ? sys.feature_names : Object.keys(FEATURE_LABELS)).map((name) => {
                    const info = FEATURE_LABELS[name as keyof typeof FEATURE_LABELS];
                    return (
                      <span key={name} className="block" title={info?.hint}>
                        {info ? info.label : name}
                        {info && <span className="ml-1 text-[10px] opacity-60">{name}</span>}
                      </span>
                    );
                  })}
                </dd>
              </div>
            </dl>
          </div>

          <div className="p-6 rounded-xl border border-kumo-hairline bg-kumo-canvas shadow-xs space-y-4">
            <div className="flex items-center gap-3 pb-3 border-b border-kumo-hairline">
              <div className="w-8 h-8 rounded-lg border border-kumo-hairline bg-kumo-recessed text-kumo-strong flex items-center justify-center">
                <HardDrives size={18} />
              </div>
              <h3 className="font-semibold text-xs uppercase tracking-wider text-kumo-strong">
                Status server
              </h3>
            </div>
            <dl className="space-y-3 text-xs">
              <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                <dt className="text-kumo-subtle font-medium">Server hidup <span className="font-mono text-[10px] opacity-60">/health</span></dt>
                <dd className="font-mono font-bold text-emerald-500">Merespons</dd>
              </div>
              <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                <dt className="text-kumo-subtle font-medium">Server siap <span className="font-mono text-[10px] opacity-60">/ready</span></dt>
                <dd className={`font-mono font-bold ${summary?.system_status === 'READY' ? 'text-emerald-500' : 'text-rose-500'}`}>
                  {summary?.system_status === 'READY' ? 'Siap' : 'Belum siap'}
                </dd>
              </div>
            </dl>
            <details className="text-xs">
              <summary className="cursor-pointer font-medium text-kumo-subtle">Detail teknis</summary>
              <dl className="space-y-3 mt-3">
                <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                  <dt className="text-kumo-subtle font-medium">Isolasi data replay</dt>
                  <dd className="font-mono text-kumo-default">Satu direktori data terpisah per ID sesi replay</dd>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                  <dt className="text-kumo-subtle font-medium">Penyimpanan</dt>
                  <dd className="font-mono font-semibold text-kumo-default">SQLite (WAL) + cache terbatas</dd>
                </div>
                <div className="flex justify-between items-center py-1.5">
                  <dt className="text-kumo-subtle font-medium">Pemrosesan alert</dt>
                  <dd className="font-mono text-kumo-default">Berurutan, tidak tumpang tindih</dd>
                </div>
              </dl>
            </details>
          </div>
        </div>
      </div>
    </>
  );
}
