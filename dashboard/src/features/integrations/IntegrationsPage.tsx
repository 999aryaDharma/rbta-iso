import { usePollingQuery } from '@/hooks/usePolling';
import { fetchIntegrations, fetchSummary } from '@/api/dashboard';
import { PageHeader } from '@/components/shared/PageHeader';
import { MetricCard } from '@/components/shared/MetricCard';
import { formatNumber } from '@/lib/formatters';
import { TERMS, TERM_HINTS } from '@/lib/labels';
import { useSearchParams } from 'react-router-dom';
import { ArrowRight, Database, Stack, ShieldCheck, PaperPlaneTilt, Plugs, ChatTeardropText } from '@phosphor-icons/react';

const STATUS_LABELS: Record<string, string> = {
  READY: 'Siap',
  ONLINE: 'Online',
  ACTIVE: 'Aktif',
  DEFERRED: TERMS.deferred,
};

function statusLabel(status: string): string {
  return STATUS_LABELS[status] ?? status;
}

export function IntegrationsPage() {
  const [searchParams] = useSearchParams();
  const runId = searchParams.get('run_id');

  const { data: integrations } = usePollingQuery(['integrations'], fetchIntegrations, 5000);
  const { data: summary } = usePollingQuery(['summary', runId || 'live'], () => fetchSummary(runId || undefined), 3000);

  const getIcon = (key: string) => {
    if (key === 'wazuh') return Database;
    if (key === 'rbta') return Stack;
    if (key === 'model') return ShieldCheck;
    if (key === 'outbox') return PaperPlaneTilt;
    if (key === 'shuffle') return Plugs;
    return ChatTeardropText;
  };

  return (
    <>
      <PageHeader
        breadcrumbs={['Operasi', 'Integrasi']}
        title="Integrasi"
        description="Status Telegram dan Shuffle. Komponen yang aktif dipisahkan dari koneksi eksternal yang belum aktif."
      />

      <div className="px-6 py-8 lg:px-10 space-y-8">
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-5">
          <MetricCard label={TERMS.rawIn} value={summary ? formatNumber(summary.raw_alert_count) : '-'} sub="Jumlah alert dari sumber data" />
          <MetricCard label="Meta-alert dibentuk" value={summary ? formatNumber(summary.meta_alert_count) : '-'} sub="Jumlah kelompok alert" />
          <MetricCard
            label="Pengurangan alert (ARR)"
            hint={TERM_HINTS.ARR}
            value={
              summary && summary.alert_reduction_rate_percent !== null && summary.alert_reduction_rate_percent !== undefined
                ? `${summary.alert_reduction_rate_percent}%`
                : '-'
            }
            sub="Pengurangan yang perlu dicek, bukan penghapusan noise"
          />
          <MetricCard label={TERMS.bucketOpen} value={summary ? formatNumber(summary.active_buckets_count) : '-'} sub="Masih menunggu alert berikutnya" />
        </div>

        <div className="space-y-4">
          {integrations &&
            Object.entries(integrations).map(([key, item], idx, arr) => {
              const Icon = getIcon(key);
              return (
                <div
                  key={key}
                  className="p-6 rounded-xl border border-kumo-hairline bg-kumo-canvas shadow-xs flex items-center justify-between transition-all hover:border-kumo-line"
                >
                  <div className="flex items-center gap-4">
                    <div className="w-10 h-10 rounded-lg border border-kumo-hairline bg-kumo-recessed text-kumo-strong flex items-center justify-center shrink-0">
                      <Icon size={20} />
                    </div>
                    <div>
                      <div className="flex items-center gap-3 mb-1">
                        <h3 className="font-semibold text-xs text-kumo-strong">
                          {item.name || key.toUpperCase()}
                        </h3>
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded text-[11px] font-mono font-medium border ${
                          item.status === 'READY' || item.status === 'ONLINE' || item.status === 'ACTIVE'
                            ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20'
                            : item.status === 'DEFERRED'
                            ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20'
                            : 'bg-kumo-recessed text-kumo-subtle border-kumo-hairline'
                        }`}>
                          {statusLabel(item.status)}
                        </span>
                      </div>
                      <p className="text-xs text-kumo-subtle max-w-3xl">
                        {item.detail || 'Komponen integrasi layanan'}
                      </p>
                      {item.status === 'DEFERRED' && <p className="mt-1 text-[11px] font-medium text-amber-700 dark:text-amber-300">Tidak didemonstrasikan sebagai integrasi live.</p>}
                    </div>
                  </div>
                  {idx < arr.length - 1 && (
                    <div className="hidden lg:flex items-center text-xs font-mono shrink-0 pl-4 text-kumo-subtle">
                      <span className="text-[11px] uppercase tracking-wider font-semibold">Tahap {idx + 1}</span>
                      <ArrowRight size={14} className="ml-1.5 text-kumo-hairline" />
                    </div>
                  )}
                </div>
              );
            })}
        </div>
      </div>
    </>
  );
}
