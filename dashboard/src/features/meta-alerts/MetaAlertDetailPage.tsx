import { useQuery } from '@tanstack/react-query';
import { useParams, useNavigate, useSearchParams } from 'react-router-dom';
import { fetchMetaAlert } from '@/api/metaAlerts';
import { PageHeader } from '@/components/shared/PageHeader';
import { DecisionBadge } from '@/components/shared/DecisionBadge';
import { formatDateTime, formatScore } from '@/lib/formatters';
import { Hint } from '@/components/shared/Hint';
import { TERM_HINTS, decisionLabel, featureLabel } from '@/lib/labels';
import { Button } from '@cloudflare/kumo/components/button';
import { ArrowRight } from '@phosphor-icons/react';
import { AnalystVerdictPanel } from './AnalystVerdictPanel';

export function MetaAlertDetailPage() {
  const { metaId } = useParams();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const runId = searchParams.get('run_id');
  const id = Number(metaId);

  const withRunId = (path: string) => (runId ? `${path}${path.includes('?') ? '&' : '?'}run_id=${encodeURIComponent(runId)}` : path);

  const { data, isLoading: isDetailLoading, isError: isDetailError, error: detailError, refetch: refetchDetail } = useQuery({
    queryKey: ['meta-alert', id, runId || 'live'],
    queryFn: () => fetchMetaAlert(id, runId || undefined),
    enabled: Number.isFinite(id),
  });

  if (!Number.isFinite(id)) {
    return (
      <div className="p-6 space-y-3">
        <p role="status" className="text-xs text-kumo-subtle">Nomor meta-alert tidak valid: “{metaId}”.</p>
        <button
          type="button"
          onClick={() => navigate(withRunId('/meta-alerts'))}
          className="px-4 py-2 rounded-lg text-sm font-semibold border border-kumo-hairline"
        >
          Kembali ke daftar
        </button>
      </div>
    );
  }

  if (isDetailLoading) {
    return <div role="status" className="p-6 text-xs text-kumo-subtle">Memuat meta-alert #{id}…</div>;
  }

  if (isDetailError || !data) {
    return (
      <div className="p-6 space-y-3">
        <p role="alert" className="text-xs text-red-600">
          Gagal memuat meta-alert #{id}{detailError instanceof Error ? `: ${detailError.message}` : ''}.
        </p>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => void refetchDetail()}
            className="px-4 py-2 rounded-lg text-sm font-semibold border border-kumo-hairline"
          >
            Coba lagi
          </button>
          <button
            type="button"
            onClick={() => navigate(withRunId('/meta-alerts'))}
            className="px-4 py-2 rounded-lg text-sm border border-kumo-hairline text-kumo-subtle"
          >
            Kembali ke daftar
          </button>
        </div>
      </div>
    );
  }

  return (
    <>
      <PageHeader
        breadcrumbs={['Analisis', 'Daftar meta-alert', `#${id}`]}
        title={`Meta-alert #${id}`}
        description={`Agen: ${data.agent_name} (${data.agent_id}) · Kategori aturan (Rule Group): ${data.rule_group_primary}`}
        actions={
          <div className="flex items-center gap-3">
            <DecisionBadge decision={data.decision} action={data.action} />
            <Button
              variant="primary"
              size="sm"
              onClick={() => navigate(withRunId(`/meta-alerts/${id}/raw-alerts`))}
            >
              Periksa {data.alert_count} alert asli <ArrowRight size={14} className="ml-1" />
            </Button>
          </div>
        }
      />

      <div className="px-6 py-8 lg:px-10 space-y-8">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="p-6 rounded-xl border border-kumo-hairline bg-kumo-canvas shadow-xs">
              <h3 className="font-semibold text-xs uppercase tracking-wider text-kumo-strong mb-4 pb-3 border-b border-kumo-hairline">
                Profil pengelompokan
              </h3>
              <dl className="space-y-3 text-xs">
                <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                  <dt className="text-kumo-subtle font-medium">Rentang waktu:</dt>
                  <dd className="font-mono text-kumo-default">{formatDateTime(data.start_time)} → {formatDateTime(data.end_time)}</dd>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                  <dt className="text-kumo-subtle font-medium">Jumlah alert digabung:</dt>
                  <dd className="font-mono font-bold text-kumo-strong">{data.alert_count} alert</dd>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                  <dt className="text-kumo-subtle font-medium">Tingkat keparahan tertinggi:</dt>
                  <dd className="font-mono font-semibold text-kumo-default">{data.max_severity} / 15</dd>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                  <dt className="text-kumo-subtle font-medium">Tingkat kepentingan aset:</dt>
                  <dd className="font-mono text-kumo-default">{data.seven_features.agent_criticality ?? 1.0}</dd>
                </div>
                <div className="flex justify-between items-center py-1">
                  <dt className="text-kumo-subtle font-medium">Taktik MITRE<Hint text={TERM_HINTS.MITRE} />:</dt>
                  <dd className="font-mono text-kumo-default text-right">{data.mitre_tactics.length ? data.mitre_tactics.join(', ') : 'Tidak ada'}</dd>
                </div>
              </dl>
            </div>

            <div className="p-6 rounded-xl border border-kumo-hairline bg-kumo-canvas shadow-xs">
              <h3 className="font-semibold text-xs uppercase tracking-wider text-kumo-strong mb-4 pb-3 border-b border-kumo-hairline">
                Penilaian Isolation Forest<Hint text={TERM_HINTS.IF} />
              </h3>
              <dl className="space-y-3 text-xs">
                <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                  <dt className="text-kumo-subtle font-medium">Skor keanehan (0–1):</dt>
                  <dd className="font-mono font-bold text-kumo-strong text-sm">{formatScore(data.anomaly_score)}</dd>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                  <dt className="text-kumo-subtle font-medium">Batas skor (Tukey):</dt>
                  <dd className="font-mono font-medium text-kumo-default">{formatScore(data.threshold_used)}</dd>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                  <dt className="text-kumo-subtle font-medium">Level:</dt>
                  <dd className="font-semibold text-kumo-default" title={decisionLabel(data.decision)?.hint}>
                    {decisionLabel(data.decision)?.label ?? data.decision}
                    {decisionLabel(data.decision) && <span className="ml-1 font-mono text-[10px] font-normal opacity-60">{data.decision}</span>}
                  </dd>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                  <dt className="text-kumo-subtle font-medium">Tindakan:</dt>
                  <dd><DecisionBadge decision={data.decision} action={data.action} /></dd>
                </div>
                {data.top_deviations && data.top_deviations.length > 0 && (
                  <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                    <dt
                      className="text-kumo-subtle font-medium"
                      title="(nilai - median reference) / IQR reference; skala 1 bila IQR reference = 0. Bukan atribusi skor Isolation Forest."
                    >
                      Penyebab skor tinggi (deviasi robust):
                    </dt>
                    <dd className="font-mono text-kumo-default text-right">
                      {data.top_deviations
                        .map(([name, value]) => `${featureLabel(name)?.label ?? name} (${name}) ${value >= 0 ? '+' : ''}${value.toFixed(1)}`)
                        .join(', ')}
                    </dd>
                  </div>
                )}
                <div className="flex justify-between items-center py-1">
                  <dt className="text-kumo-subtle font-medium">Versi model:</dt>
                  <dd className="font-mono text-kumo-subtle">{data.model_version}</dd>
                </div>
              </dl>
            </div>
          </div>
        {!runId && <AnalystVerdictPanel key={id} metaId={id} current={data.analyst_verdict} />}
      </div>
    </>
  );
}
