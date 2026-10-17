import { useSearchParams, useNavigate } from 'react-router-dom';
import { usePollingQuery } from '@/hooks/usePolling';
import { fetchSummary, fetchTimeseries } from '@/api/dashboard';
import { fetchMetaAlerts } from '@/api/metaAlerts';
import { resolveLiveContext } from '@/features/live/liveContext';
import { MetricCard } from '@/components/shared/MetricCard';
import { PageHeader } from '@/components/shared/PageHeader';
import { DecisionBadge } from '@/components/shared/DecisionBadge';
import { formatNumber, formatDateTime, formatScore } from '@/lib/formatters';
import { ACTION_LABELS, TERM_HINTS, TERMS } from '@/lib/labels';
import { Button } from '@cloudflare/kumo/components/button';
import { Badge } from '@cloudflare/kumo/components/badge';
import { Table } from '@cloudflare/kumo/components/table';
import { WarningCircle, ArrowRight } from '@phosphor-icons/react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts';

export function OverviewPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const runId = searchParams.get('run_id');

  const withRunId = (path: string) => (runId ? `${path}${path.includes('?') ? '&' : '?'}run_id=${encodeURIComponent(runId)}` : path);

  const { data: summary } = usePollingQuery(['summary', runId || 'live'], () => fetchSummary(runId || undefined), 3000);
  const { data: timeseries } = usePollingQuery(['timeseries', runId || 'live'], () => fetchTimeseries(24, runId || undefined), 5000);
  const { data: recentMetas } = usePollingQuery(
    ['meta-alerts-recent', runId || 'live'],
    () => fetchMetaAlerts({ page: 1, page_size: 10, sort_by: 'end_time', sort_order: 'desc', run_id: runId || undefined }),
    5000,
  );

  const needsInvestigation = recentMetas?.items.filter((m) => m.action === 'ESCALATE') || [];
  const mode = resolveLiveContext(runId);
  const isReplay = mode === 'replay';

  return (
    <>
      <PageHeader
        breadcrumbs={isReplay ? ['Riset', 'Ringkasan replay'] : ['Operasi', 'Ringkasan live']}
        title={isReplay ? 'Ringkasan replay' : 'Ringkasan live'}
        description={
          isReplay
            ? `Kondisi alert dan beban analyst dari data historis sesi replay ${runId}. Definisi angka sama dengan live; skor keanehan = urutan prioritas, bukan vonis serangan.`
            : 'Kondisi alert dan beban analyst saat ini (data langsung). RBTA mengurangi jumlah yang perlu dicek analyst; skor keanehan = urutan prioritas, bukan vonis serangan.'
        }
      />

      <div className="px-6 py-8 lg:px-10 space-y-8">
        <p className="text-xs text-kumo-subtle leading-relaxed border border-kumo-hairline bg-kumo-canvas rounded-xl px-4 py-3">
          {isReplay
            ? `Konteks replay: data historis (sesi ${runId}). ARR = pengurangan jumlah yang perlu dicek analyst, bukan akurasi; skor = prioritas, bukan vonis serangan.`
            : 'Konteks live: data langsung dari Indexer/API. ARR = pengurangan jumlah yang perlu dicek analyst, bukan akurasi; skor = prioritas, bukan vonis serangan.'}
        </p>
        {needsInvestigation.length > 0 && (
          <div className="p-6 rounded-xl bg-rose-500/5 shadow-xs space-y-5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-rose-500/20">
              <div className="flex items-center gap-3">
                <WarningCircle size={22} className="text-rose-600 dark:text-rose-400 shrink-0" weight="fill" />
                <h2 className="text-xs font-semibold uppercase tracking-wider text-kumo-strong">
                  Perlu dicek segera ({needsInvestigation.length} meta-alert, kode ESCALATE)
                </h2>
              </div>
              <Button
                variant="ghost"
                size="sm"
                className="text-xs text-rose-600 dark:text-rose-400 hover:text-rose-700"
                onClick={() => navigate(withRunId('/meta-alerts?action=ESCALATE'))}
              >
                Lihat semua yang perlu dicek <ArrowRight size={14} className="ml-1" />
              </Button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
              {needsInvestigation.slice(0, 3).map((m) => (
                <div
                  key={m.meta_id}
                  onClick={() => navigate(withRunId(`/meta-alerts/${m.meta_id}`))}
                  className="p-5 rounded-xl border border-kumo-hairline bg-kumo-canvas cursor-pointer transition-all hover:border-kumo-strong hover:shadow-xs space-y-3"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-bold text-kumo-strong">#{m.meta_id}</span>
                    <DecisionBadge decision={m.decision} action={m.action} />
                  </div>
                  <div className="space-y-2 text-xs text-kumo-subtle">
                    <div className="flex justify-between items-center">
                      <span>Agen:</span>
                      <span className="text-kumo-default font-medium truncate max-w-[160px]">{m.agent_name} ({m.agent_id})</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span>Kategori aturan:</span>
                      <Badge variant="secondary">{m.rule_group_primary}</Badge>
                    </div>
                    <div className="flex justify-between items-center">
                      <span>Skor / batas skor:</span>
                      <span className="font-mono text-kumo-strong font-semibold">{m.anomaly_score.toFixed(3)} / {m.threshold_used.toFixed(3)}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span>Alert digabung:</span>
                      <span className="font-mono font-bold text-kumo-strong">{m.alert_count}</span>
                    </div>
                  </div>
                  <Button
                    variant="primary"
                    size="sm"
                    className="w-full justify-center text-xs mt-2"
                    onClick={(e) => {
                      e.stopPropagation();
                      navigate(withRunId(`/meta-alerts/${m.meta_id}`));
                    }}
                  >
                    Periksa {m.alert_count} alert asli <ArrowRight size={13} className="ml-1" />
                  </Button>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="grid grid-cols-2 lg:grid-cols-4 gap-5">
          <MetricCard
            label="Alert masuk"
            value={summary ? formatNumber(summary.raw_alert_count) : '-'}
            sub={isReplay ? 'Alert valid dari data historis' : 'Alert Wazuh dari data langsung'}
          />
          <MetricCard
            label="Meta-alert selesai"
            value={summary ? formatNumber(summary.meta_alert_count) : '-'}
            sub="Kelompok alert hasil pengelompokan RBTA"
            hint={TERM_HINTS.RBTA}
          />
          <MetricCard
            label="Pengurangan alert (ARR)"
            value={
              summary && summary.alert_reduction_rate_percent !== null && summary.alert_reduction_rate_percent !== undefined
                ? `${summary.alert_reduction_rate_percent}%`
                : '-'
            }
            sub="Pengurangan yang perlu dicek, bukan akurasi"
            hint={TERM_HINTS.ARR}
          />
          <div
            onClick={() => navigate(withRunId('/meta-alerts?action=ESCALATE'))}
            className="cursor-pointer transition-opacity hover:opacity-95"
          >
            <MetricCard
              label="Perlu dicek segera"
              value={summary ? formatNumber(summary.escalate_count) : '-'}
              sub="Kode ESCALATE. Prioritas, bukan insiden terbukti"
              hint={ACTION_LABELS.ESCALATE.hint}
            />
          </div>
          <MetricCard
            label="Melewati batas skor"
            value={summary ? formatNumber(summary.anomalies_detected) : '-'}
            sub="Skor di atas batas; prioritas, bukan vonis serangan"
          />
          <div
            onClick={() => navigate(withRunId('/rbta'))}
            className="cursor-pointer transition-opacity hover:opacity-95"
          >
            <MetricCard
              label="Kelompok alert terbuka"
              value={summary ? formatNumber(summary.active_buckets_count) : '-'}
              sub={isReplay ? 'Kelompok per agen pada sesi replay ini' : 'Kelompok per agen pada data langsung'}
            />
          </div>
          <MetricCard
            label="Ringkasan harian"
            value={summary ? formatNumber(summary.digest_count) : '-'}
            sub="Kode DAILY_DIGEST. Ditinjau berkala"
            hint={ACTION_LABELS.DAILY_DIGEST.hint}
          />
          <MetricCard
            label="Tidak ditampilkan di antrean"
            value={summary ? formatNumber(summary.suppress_count) : '-'}
            sub="Kode SUPPRESS. Prioritas rendah, bukan label aman"
            hint={ACTION_LABELS.SUPPRESS.hint}
          />
        </div>

        {timeseries && Array.isArray(timeseries) && timeseries.length > 0 && (
          <div className="p-6 rounded-xl border border-kumo-hairline bg-kumo-canvas shadow-xs space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-kumo-hairline">
              <div>
                <h2 className="text-sm font-semibold text-kumo-strong">
                  {TERMS.processingRate}
                </h2>
                <p className="text-xs text-kumo-subtle mt-0.5">
                  {isReplay
                    ? 'Alert historis vs meta-alert selesai per waktu (sesi replay ini)'
                    : 'Alert masuk vs meta-alert selesai per waktu'}
                </p>
              </div>
            </div>
            <ResponsiveContainer width="100%" height={260}>
              <AreaChart data={timeseries}>
                <CartesianGrid strokeDasharray="3 3" opacity={0.15} />
                <XAxis dataKey="timestamp" tick={{ fontSize: 11 }} />
                <YAxis tick={{ fontSize: 11 }} />
                <Tooltip />
                <Legend wrapperStyle={{ fontSize: '12px' }} />
                <Area type="monotone" dataKey="raw_alerts" stroke="#64748b" fill="#64748b20" name="Alert masuk" />
                <Area type="monotone" dataKey="meta_alerts" stroke="#0f172a" fill="#0f172a20" name="Meta-alert" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}

        {recentMetas && recentMetas.items.length > 0 && (
          <div className="rounded-xl border border-kumo-hairline bg-kumo-canvas shadow-xs overflow-hidden">
            <div className="px-6 py-4 border-b border-kumo-hairline flex items-center justify-between">
              <div>
                <h2 className="text-sm font-semibold text-kumo-strong">
                  Meta-alert terbaru
                </h2>
                <p className="text-xs text-kumo-subtle mt-0.5">
                  Kelompok alert yang dinilai Isolation Forest; skor = prioritas, bukan vonis serangan
                </p>
              </div>
              <Button
                variant="secondary"
                size="sm"
                onClick={() => navigate(withRunId('/meta-alerts'))}
              >
                Lihat semua meta-alert <ArrowRight size={13} className="ml-1" />
              </Button>
            </div>
            <Table>
              <Table.Header>
                <Table.Row className="bg-kumo-recessed/50 text-[11px] uppercase tracking-wider">
                  <Table.Head>Nomor</Table.Head>
                  <Table.Head>Waktu selesai</Table.Head>
                  <Table.Head>Agen</Table.Head>
                  <Table.Head>Kategori aturan (Rule Group)</Table.Head>
                  <Table.Head className="text-right">Jumlah alert</Table.Head>
                  <Table.Head className="text-right">Skor keanehan</Table.Head>
                  <Table.Head>Level & aksi</Table.Head>
                </Table.Row>
              </Table.Header>
              <Table.Body>
                {recentMetas.items.map((m) => (
                  <Table.Row
                    key={m.meta_id}
                    className="cursor-pointer hover:bg-kumo-recessed/40 transition-colors text-xs"
                    onClick={() => navigate(withRunId(`/meta-alerts/${m.meta_id}`))}
                  >
                    <Table.Cell className="font-mono font-semibold text-kumo-strong">#{m.meta_id}</Table.Cell>
                    <Table.Cell className="text-kumo-subtle">{formatDateTime(m.end_time)}</Table.Cell>
                    <Table.Cell className="font-medium text-kumo-default">{m.agent_name} <span className="text-kumo-subtle text-[11px]">({m.agent_id})</span></Table.Cell>
                    <Table.Cell className="font-mono text-kumo-default">{m.rule_group_primary}</Table.Cell>
                    <Table.Cell className="text-right font-mono font-bold text-kumo-strong">{m.alert_count}</Table.Cell>
                    <Table.Cell className="text-right font-mono text-kumo-default">{formatScore(m.anomaly_score)}</Table.Cell>
                    <Table.Cell><DecisionBadge decision={m.decision} action={m.action} /></Table.Cell>
                  </Table.Row>
                ))}
              </Table.Body>
            </Table>
          </div>
        )}
      </div>
    </>
  );
}
