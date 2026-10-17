import { useQuery } from '@tanstack/react-query';
import { useParams, useNavigate, useSearchParams } from 'react-router-dom';
import { fetchMetaAlert } from '@/api/metaAlerts';
import { PageHeader } from '@/components/shared/PageHeader';
import { DecisionBadge } from '@/components/shared/DecisionBadge';
import { formatDateTime, formatScore } from '@/lib/formatters';
import { Button } from '@cloudflare/kumo/components/button';
import { ArrowRight } from '@phosphor-icons/react';

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
        <p role="status" className="text-xs text-kumo-subtle">ID MetaAlert tidak valid: “{metaId}”.</p>
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
    return <div role="status" className="p-6 text-xs text-kumo-subtle">Loading MetaAlert #{id}...</div>;
  }

  if (isDetailError || !data) {
    return (
      <div className="p-6 space-y-3">
        <p role="alert" className="text-xs text-red-600">
          Gagal memuat MetaAlert #{id}{detailError instanceof Error ? `: ${detailError.message}` : ''}.
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
        breadcrumbs={['Security Analytics', 'MetaAlerts', `#${id}`]}
        title={`MetaAlert #${id}`}
        description={`Agent: ${data.agent_name} (${data.agent_id}) · Primary Rule Group: ${data.rule_group_primary}`}
        actions={
          <div className="flex items-center gap-3">
            <DecisionBadge decision={data.decision} action={data.action} />
            <Button
              variant="primary"
              size="sm"
              onClick={() => navigate(withRunId(`/meta-alerts/${id}/raw-alerts`))}
            >
              Investigate {data.alert_count} Raw Alerts <ArrowRight size={14} className="ml-1" />
            </Button>
          </div>
        }
      />

      <div className="px-6 py-8 lg:px-10 space-y-8">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="p-6 rounded-xl border border-kumo-hairline bg-kumo-canvas shadow-xs">
              <h3 className="font-semibold text-xs uppercase tracking-wider text-kumo-strong mb-4 pb-3 border-b border-kumo-hairline">
                Temporal Aggregation Profile
              </h3>
              <dl className="space-y-3 text-xs">
                <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                  <dt className="text-kumo-subtle font-medium">Cluster Window:</dt>
                  <dd className="font-mono text-kumo-default">{formatDateTime(data.start_time)} → {formatDateTime(data.end_time)}</dd>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                  <dt className="text-kumo-subtle font-medium">Aggregated Event Count:</dt>
                  <dd className="font-mono font-bold text-kumo-strong">{data.alert_count} events</dd>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                  <dt className="text-kumo-subtle font-medium">Max Rule Severity:</dt>
                  <dd className="font-mono font-semibold text-kumo-default">{data.max_severity} / 15</dd>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                  <dt className="text-kumo-subtle font-medium">Agent Criticality Weight:</dt>
                  <dd className="font-mono text-kumo-default">{data.seven_features.agent_criticality ?? 1.0}</dd>
                </div>
                <div className="flex justify-between items-center py-1">
                  <dt className="text-kumo-subtle font-medium">MITRE Tactics Present:</dt>
                  <dd className="font-mono text-kumo-default text-right">{data.mitre_tactics.length ? data.mitre_tactics.join(', ') : 'None'}</dd>
                </div>
              </dl>
            </div>

            <div className="p-6 rounded-xl border border-kumo-hairline bg-kumo-canvas shadow-xs">
              <h3 className="font-semibold text-xs uppercase tracking-wider text-kumo-strong mb-4 pb-3 border-b border-kumo-hairline">
                Isolation Forest Evaluation & Scoring
              </h3>
              <dl className="space-y-3 text-xs">
                <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                  <dt className="text-kumo-subtle font-medium">Calibrated Anomaly Score:</dt>
                  <dd className="font-mono font-bold text-kumo-strong text-sm">{formatScore(data.anomaly_score)}</dd>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                  <dt className="text-kumo-subtle font-medium">Deterministic Tukey Threshold:</dt>
                  <dd className="font-mono font-medium text-kumo-default">{formatScore(data.threshold_used)}</dd>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                  <dt className="text-kumo-subtle font-medium">Alert Level:</dt>
                  <dd className="font-semibold text-kumo-default">{data.decision}</dd>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                  <dt className="text-kumo-subtle font-medium">SOC Action Trigger:</dt>
                  <dd><DecisionBadge decision={data.decision} action={data.action} /></dd>
                </div>
                <div className="flex justify-between items-center py-1">
                  <dt className="text-kumo-subtle font-medium">Model Artifact Registry:</dt>
                  <dd className="font-mono text-kumo-subtle">{data.model_version}</dd>
                </div>
              </dl>
            </div>
          </div>
      </div>
    </>
  );
}
