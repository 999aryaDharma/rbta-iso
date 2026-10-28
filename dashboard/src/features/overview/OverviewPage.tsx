import { useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { usePollingQuery } from '@/hooks/usePolling';
import { fetchSummary, fetchTimeseries, fetchFilterOptions, type OverviewScope } from '@/api/dashboard';
import { fetchMetaAlerts } from '@/api/metaAlerts';
import { resolveLiveContext } from '@/features/live/liveContext';
import { PageHeader } from '@/components/shared/PageHeader';
import { DecisionBadge } from '@/components/shared/DecisionBadge';
import { Hint } from '@/components/shared/Hint';
import { formatNumber, formatDateTime, formatScore } from '@/lib/formatters';
import { ACTION_LABELS, TERM_HINTS, TERMS } from '@/lib/labels';
import { Button } from '@cloudflare/kumo/components/button';
import { Select } from '@cloudflare/kumo/components/select';
import { Table } from '@cloudflare/kumo/components/table';
import { DatePicker, type DateRange } from '@cloudflare/kumo/components/date-picker';
import { WarningCircle, ArrowRight, CalendarBlank } from '@phosphor-icons/react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts';

const ALL = '__all__';

function Kpi({ label, value, sub, hint, onClick }: {
  label: string;
  value: string;
  sub: string;
  hint?: string;
  onClick?: () => void;
}) {
  const body = (
    <>
      <span className="text-sm text-kumo-subtle">{label}{hint && <Hint text={hint} />}</span>
      <span className="font-mono text-2xl font-semibold text-kumo-strong">{value}</span>
      <span className="text-sm text-kumo-subtle">{sub}</span>
    </>
  );
  const cls = 'grid gap-1.5 rounded-xl bg-kumo-canvas px-5 py-4 ring ring-kumo-line text-left';
  return onClick ? (
    <button type="button" onClick={onClick} className={`${cls} hover:bg-kumo-recessed`}>{body}</button>
  ) : (
    <div className={cls}>{body}</div>
  );
}

function SectionTitle({ title, description }: { title: string; description?: string }) {
  return (
    <div className="grid gap-1.5">
      <h2 className="text-base font-semibold text-kumo-strong">{title}</h2>
      {description && <p className="text-sm text-kumo-subtle">{description}</p>}
    </div>
  );
}

export function OverviewPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const runId = searchParams.get('run_id');
  const withRunId = (path: string) => (runId ? `${path}${path.includes('?') ? '&' : '?'}run_id=${encodeURIComponent(runId)}` : path);

  const [range, setRange] = useState<DateRange | undefined>();
  const [pickerOpen, setPickerOpen] = useState(false);
  const [agentId, setAgentId] = useState(ALL);
  const [ruleGroup, setRuleGroup] = useState(ALL);

  // Rentang kustom = awal hari s/d akhir hari (UTC, sesuai bin per jam di backend).
  const rangeParam = range?.from
    ? {
        start: `${range.from.toLocaleDateString('sv')}T00:00:00Z`,
        end: `${(range.to ?? range.from).toLocaleDateString('sv')}T23:59:59Z`,
      }
    : undefined;
  const scope: OverviewScope = {
    ...rangeParam,
    agent_id: agentId === ALL ? undefined : agentId,
    rule_group_primary: ruleGroup === ALL ? undefined : ruleGroup,
  };
  const scopeKey = JSON.stringify(scope);
  const isFiltered = Object.values(scope).some(Boolean);

  const { data: options } = usePollingQuery(['overview-filters', runId || 'live'], () => fetchFilterOptions(runId || undefined), 30000);
  const { data: summary, isError: summaryError } = usePollingQuery(
    ['summary', runId || 'live', scopeKey],
    () => fetchSummary(runId || undefined, scope),
    3000,
  );
  const { data: timeseries } = usePollingQuery(
    ['timeseries', runId || 'live', scopeKey],
    () => fetchTimeseries(24, runId || undefined, scope),
    5000,
  );
  const { data: queue } = usePollingQuery(
    ['overview-queue', runId || 'live', scopeKey],
    () => fetchMetaAlerts({ ...scope, action: 'ESCALATE', page: 1, page_size: 5, sort_by: 'anomaly_score', sort_order: 'desc', run_id: runId || undefined }),
    5000,
  );
  const { data: recentMetas } = usePollingQuery(
    ['meta-alerts-recent', runId || 'live', scopeKey],
    () => fetchMetaAlerts({ ...scope, page: 1, page_size: 10, sort_by: 'end_time', sort_order: 'desc', run_id: runId || undefined }),
    5000,
  );

  const isReplay = resolveLiveContext(runId) === 'replay';
  const num = (v: number | undefined) => (summary && v !== undefined ? formatNumber(v) : '-');
  const reset = () => { setRange(undefined); setPickerOpen(false); setAgentId(ALL); setRuleGroup(ALL); };

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

      <div className="sticky top-0 z-10 border-b border-kumo-line bg-kumo-canvas px-6 py-3 lg:px-10">
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="secondary" size="sm" onClick={() => setPickerOpen((o) => !o)}>
            <CalendarBlank size={14} className="mr-1" />
            {rangeParam
              ? `${range!.from!.toLocaleDateString('sv')} – ${(range!.to ?? range!.from!).toLocaleDateString('sv')}`
              : 'Semua waktu'}
          </Button>
          <Select
            size="sm"
            value={agentId}
            onValueChange={(v) => setAgentId(v as string)}
            placeholder="Semua agen"
          >
            <Select.Option value={ALL}>Semua agen</Select.Option>
            {(options?.agents ?? []).map((a) => (
              <Select.Option key={a.agent_id} value={a.agent_id}>{a.agent_name} ({a.agent_id})</Select.Option>
            ))}
          </Select>
          <Select
            size="sm"
            value={ruleGroup}
            onValueChange={(v) => setRuleGroup(v as string)}
            placeholder="Semua kategori aturan"
          >
            <Select.Option value={ALL}>Semua kategori aturan</Select.Option>
            {(options?.rule_groups ?? []).map((g) => (
              <Select.Option key={g} value={g}>{g}</Select.Option>
            ))}
          </Select>
          {isFiltered && (
            <Button variant="ghost" size="sm" onClick={reset}>Reset filter</Button>
          )}
        </div>
        {pickerOpen && (
          <div className="mt-3 flex">
            <DatePicker mode="range" selected={range} onChange={setRange} numberOfMonths={2} />
          </div>
        )}
      </div>

      <div className="grid gap-8 px-6 py-8 lg:px-10">
        <p className="text-sm text-kumo-subtle">
          {isReplay
            ? `Konteks replay: data historis (sesi ${runId}). ARR = pengurangan jumlah yang perlu dicek analyst, bukan akurasi; skor = prioritas, bukan vonis serangan.`
            : 'Konteks live: data langsung dari Indexer/API. ARR = pengurangan jumlah yang perlu dicek analyst, bukan akurasi; skor = prioritas, bukan vonis serangan.'}
          {isFiltered && ' Angka di bawah mengikuti filter yang aktif.'}
        </p>

        {summaryError && (
          <p role="alert" className="text-sm text-rose-600 dark:text-rose-400">
            Ringkasan gagal dimuat. Angka di bawah mungkin tidak terbaru; percobaan ulang berjalan otomatis.
          </p>
        )}

        <section className="grid gap-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2.5">
              <span className="h-lh flex items-center">
                <WarningCircle size={20} weight="fill" className="text-rose-600 dark:text-rose-400" />
              </span>
              <SectionTitle
                title="Perlu dicek segera"
                description={`Kode ESCALATE, diurutkan dari skor tertinggi. ${ACTION_LABELS.ESCALATE.hint}`}
              />
            </div>
            <Button variant="secondary" size="sm" onClick={() => navigate(withRunId('/meta-alerts?action=ESCALATE'))}>
              Lihat semua ({num(summary?.escalate_count)}) <ArrowRight size={13} className="ml-1" />
            </Button>
          </div>
          <div className="overflow-hidden rounded-xl bg-kumo-canvas ring ring-kumo-line">
            {queue && queue.items.length === 0 ? (
              <p className="px-5 py-6 text-sm text-kumo-subtle">
                Tidak ada meta-alert yang perlu dicek{isFiltered ? ' pada filter ini' : ' saat ini'}.
              </p>
            ) : (
              <Table>
                <Table.Header>
                  <Table.Row className="bg-kumo-recessed text-sm">
                    <Table.Head>Nomor</Table.Head>
                    <Table.Head>Agen</Table.Head>
                    <Table.Head>Kategori aturan</Table.Head>
                    <Table.Head className="text-right">Jumlah alert</Table.Head>
                    <Table.Head className="text-right">Skor / batas</Table.Head>
                    <Table.Head>Waktu selesai</Table.Head>
                    <Table.Head><span className="sr-only">Aksi</span></Table.Head>
                  </Table.Row>
                </Table.Header>
                <Table.Body>
                  {(queue?.items ?? []).map((m) => (
                    <Table.Row
                      key={m.meta_id}
                      className="cursor-pointer text-sm hover:bg-kumo-recessed"
                      onClick={() => navigate(withRunId(`/meta-alerts/${m.meta_id}`))}
                    >
                      <Table.Cell className="font-mono font-medium text-kumo-strong">#{m.meta_id}</Table.Cell>
                      <Table.Cell className="text-kumo-default">{m.agent_name} <span className="text-kumo-subtle">({m.agent_id})</span></Table.Cell>
                      <Table.Cell className="font-mono text-kumo-default">{m.rule_group_primary}</Table.Cell>
                      <Table.Cell className="text-right font-mono text-kumo-strong">{m.alert_count}</Table.Cell>
                      <Table.Cell className="text-right font-mono text-kumo-strong">{m.anomaly_score.toFixed(3)} / {m.threshold_used.toFixed(3)}</Table.Cell>
                      <Table.Cell className="text-kumo-subtle">{formatDateTime(m.end_time)}</Table.Cell>
                      <Table.Cell className="text-right">
                        <Button
                          variant="primary"
                          size="sm"
                          onClick={(e) => { e.stopPropagation(); navigate(withRunId(`/meta-alerts/${m.meta_id}`)); }}
                        >
                          Periksa {m.alert_count} alert asli
                        </Button>
                      </Table.Cell>
                    </Table.Row>
                  ))}
                </Table.Body>
              </Table>
            )}
          </div>
        </section>

        <section className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <Kpi
            label="Perlu dicek segera"
            value={num(summary?.escalate_count)}
            sub="Prioritas, bukan insiden terbukti"
            hint={`Kode ESCALATE. ${ACTION_LABELS.ESCALATE.hint}`}
            onClick={() => navigate(withRunId('/meta-alerts?action=ESCALATE'))}
          />
          <Kpi
            label="Meta-alert selesai"
            value={num(summary?.meta_alert_count)}
            sub={`Dari ${num(summary?.raw_alert_count)} alert masuk`}
            hint={TERM_HINTS.RBTA}
          />
          <Kpi
            label="Pengurangan alert (ARR)"
            value={
              summary && summary.alert_reduction_rate_percent !== null && summary.alert_reduction_rate_percent !== undefined
                ? `${summary.alert_reduction_rate_percent}%`
                : '-'
            }
            sub="Bukan akurasi deteksi"
            hint={TERM_HINTS.ARR}
          />
          <Kpi
            label="Kelompok alert terbuka"
            value={num(summary?.active_buckets_count)}
            sub={isReplay ? 'Per agen, sesi replay ini' : 'Per agen, data langsung'}
            onClick={() => navigate(withRunId('/rbta'))}
          />
        </section>

        <section className="grid gap-4 lg:grid-cols-3">
          <div className="grid gap-4 rounded-xl bg-kumo-canvas px-5 py-4 ring ring-kumo-line lg:col-span-2">
            <SectionTitle
              title={TERMS.processingRate}
              description={
                (isReplay
                  ? 'Alert historis vs meta-alert selesai per waktu (sesi replay ini)'
                  : 'Alert masuk vs meta-alert selesai per waktu')
                + (rangeParam ? '' : ' · 24 jam terakhir')
              }
            />
            {timeseries && timeseries.length > 0 ? (
              <ResponsiveContainer width="100%" height={240}>
                <AreaChart data={timeseries}>
                  <CartesianGrid strokeDasharray="3 3" opacity={0.15} />
                  <XAxis dataKey="timestamp" tick={{ fontSize: 12 }} />
                  <YAxis tick={{ fontSize: 12 }} />
                  <Tooltip />
                  <Legend wrapperStyle={{ fontSize: '14px' }} />
                  <Area type="monotone" dataKey="raw_alerts" stroke="#64748b" fill="#64748b20" name="Alert masuk" />
                  <Area type="monotone" dataKey="meta_alerts" stroke="#0f172a" fill="#0f172a20" name="Meta-alert" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <p className="text-sm text-kumo-subtle">Belum ada data pada rentang ini.</p>
            )}
          </div>

          <div className="grid content-start gap-4 rounded-xl bg-kumo-canvas px-5 py-4 ring ring-kumo-line">
            <SectionTitle title="Sebaran aksi" description="Seluruh meta-alert pada filter aktif" />
            <dl className="grid gap-3 text-sm">
              {[
                ['Perlu dicek segera', summary?.escalate_count, 'Prioritas'],
                ['Ringkasan harian', summary?.digest_count, 'Ditinjau berkala'],
                ['Tidak ditampilkan', summary?.suppress_count, 'Bukan label aman'],
                ['Melewati batas skor', summary?.anomalies_detected, 'Prioritas, bukan vonis serangan'],
              ].map(([label, value, note]) => (
                <div key={label as string} className="grid gap-0.5">
                  <div className="flex items-baseline justify-between">
                    <dt className="text-kumo-default">{label as string}</dt>
                    <dd className="font-mono font-medium text-kumo-strong">{num(value as number | undefined)}</dd>
                  </div>
                  <span className="text-kumo-subtle">{note as string}</span>
                </div>
              ))}
            </dl>
          </div>
        </section>

        <section className="grid gap-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <SectionTitle
              title="Meta-alert terbaru"
              description="Kelompok alert yang dinilai Isolation Forest; skor = prioritas, bukan vonis serangan"
            />
            <Button variant="secondary" size="sm" onClick={() => navigate(withRunId('/meta-alerts'))}>
              Lihat semua meta-alert <ArrowRight size={13} className="ml-1" />
            </Button>
          </div>
          <div className="overflow-hidden rounded-xl bg-kumo-canvas ring ring-kumo-line">
            {recentMetas && recentMetas.items.length === 0 ? (
              <p className="px-5 py-6 text-sm text-kumo-subtle">Belum ada meta-alert{isFiltered ? ' pada filter ini' : ''}.</p>
            ) : (
              <Table>
                <Table.Header>
                  <Table.Row className="bg-kumo-recessed text-sm">
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
                  {(recentMetas?.items ?? []).map((m) => (
                    <Table.Row
                      key={m.meta_id}
                      className="cursor-pointer text-sm hover:bg-kumo-recessed"
                      onClick={() => navigate(withRunId(`/meta-alerts/${m.meta_id}`))}
                    >
                      <Table.Cell className="font-mono font-medium text-kumo-strong">#{m.meta_id}</Table.Cell>
                      <Table.Cell className="text-kumo-subtle">{formatDateTime(m.end_time)}</Table.Cell>
                      <Table.Cell className="text-kumo-default">{m.agent_name} <span className="text-kumo-subtle">({m.agent_id})</span></Table.Cell>
                      <Table.Cell className="font-mono text-kumo-default">{m.rule_group_primary}</Table.Cell>
                      <Table.Cell className="text-right font-mono text-kumo-strong">{m.alert_count}</Table.Cell>
                      <Table.Cell className="text-right font-mono text-kumo-default">{formatScore(m.anomaly_score)}</Table.Cell>
                      <Table.Cell><DecisionBadge decision={m.decision} action={m.action} /></Table.Cell>
                    </Table.Row>
                  ))}
                </Table.Body>
              </Table>
            )}
          </div>
        </section>
      </div>
    </>
  );
}
