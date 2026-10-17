import { usePollingQuery } from '@/hooks/usePolling';
import { fetchSystemInfo, fetchSummary } from '@/api/dashboard';
import { PageHeader } from '@/components/shared/PageHeader';
import { MetricCard } from '@/components/shared/MetricCard';
import { LiveStatusCard } from '@/features/live/LiveStatusPanel';
import { useSearchParams } from 'react-router-dom';
import { HardDrives, Cpu } from '@phosphor-icons/react';

export function SystemPage() {
  const [searchParams] = useSearchParams();
  const runId = searchParams.get('run_id');

  const { data: sys } = usePollingQuery(['system', runId || 'live'], () => fetchSystemInfo(runId || undefined), 3000);
  const { data: summary } = usePollingQuery(['summary', runId || 'live'], () => fetchSummary(runId || undefined), 3000);

  return (
    <>
      <PageHeader
        breadcrumbs={['Operations', 'System Diagnostics']}
        title="System Configuration & Diagnostics"
        description="Runtime architecture, active model bundle parameters, schema invariants, and persistent evidence storage"
      />

      <div className="px-6 py-8 lg:px-10 space-y-8">
        <LiveStatusCard />
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-5">
          <MetricCard label="System Status" value={sys?.system_status ?? '-'} sub="Nilai aktual dari API" />
          <MetricCard label="Model Version" value={sys?.model_version ?? '-'} sub="Registered bundle" />
          <MetricCard label="Tukey Threshold" value={sys ? sys.tukey_threshold.toFixed(4) : '-'} sub="Calibrated anomaly boundary" />
          <MetricCard label="Base Δt (Seconds)" value={sys ? `${sys.base_delta_t_seconds}s` : '-'} sub="Initial aggregation window" />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="p-6 rounded-xl border border-kumo-hairline bg-kumo-canvas shadow-xs space-y-4">
            <div className="flex items-center gap-3 pb-3 border-b border-kumo-hairline">
              <div className="w-8 h-8 rounded-lg border border-kumo-hairline bg-kumo-recessed text-kumo-strong flex items-center justify-center">
                <Cpu size={18} />
              </div>
              <h3 className="font-semibold text-xs uppercase tracking-wider text-kumo-strong">
                Active Isolation Forest Bundle
              </h3>
            </div>
            <dl className="space-y-3 text-xs">
              <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                <dt className="text-kumo-subtle font-medium">Model Artifact Version</dt>
                <dd className="font-mono font-semibold text-kumo-strong">{sys?.model_version ?? '-'}</dd>
              </div>
              <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                <dt className="text-kumo-subtle font-medium">Tukey IQR Anomaly Threshold</dt>
                <dd className="font-mono font-bold text-kumo-strong">
                  {sys ? sys.tukey_threshold.toFixed(4) : '-'}
                </dd>
              </div>
              <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                <dt className="text-kumo-subtle font-medium">Random State Seed</dt>
                <dd className="font-mono text-kumo-default">{sys?.random_state ?? 'None'}</dd>
              </div>
              <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                <dt className="text-kumo-subtle font-medium">Adaptive Temporal Clustering</dt>
                <dd className="font-mono font-semibold text-kumo-default">{sys?.adaptive ? 'ENABLED' : 'DISABLED'}</dd>
              </div>
              <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                <dt className="text-kumo-subtle font-medium">Decision Strategy</dt>
                <dd className="font-mono text-kumo-default">FOUR_QUADRANT_MATRIX</dd>
              </div>
              <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                <dt className="text-kumo-subtle font-medium">Feature Normalization</dt>
                <dd className="font-mono text-kumo-default">RobustScaler (Median / IQR)</dd>
              </div>
              <div className="pt-1">
                <dt className="text-kumo-subtle font-medium mb-1.5">Seven Features (Locked Canonical Order)</dt>
                <dd className="font-mono text-[11px] p-3.5 rounded-lg border border-kumo-hairline bg-kumo-recessed/30 text-kumo-default leading-relaxed">
                  {sys?.feature_names && sys.feature_names.length > 0
                    ? sys.feature_names.join(', ')
                    : 'max_severity, mitre_tactic_count, critical_mitre_tactic_present, alert_count_log, rule_diversity_shannon, severity_dispersion, agent_criticality'}
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
                Runtime & Persistence Diagnostics
              </h3>
            </div>
            <dl className="space-y-3 text-xs">
              <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                <dt className="text-kumo-subtle font-medium">Liveness Probe (/health)</dt>
                <dd className="font-mono font-bold text-emerald-500">API responding</dd>
              </div>
              <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                <dt className="text-kumo-subtle font-medium">Readiness Probe (/ready)</dt>
                <dd className={`font-mono font-bold ${summary?.system_status === 'READY' ? 'text-emerald-500' : 'text-rose-500'}`}>
                  {summary?.system_status === 'READY' ? '200 READY' : '503 NOT READY'}
                </dd>
              </div>
              <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                <dt className="text-kumo-subtle font-medium">Replay Isolation Layer</dt>
                <dd className="font-mono text-kumo-default">Sandboxed Data Directory per Run ID</dd>
              </div>
              <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                <dt className="text-kumo-subtle font-medium">Persistence Mode</dt>
                <dd className="font-mono font-semibold text-kumo-default">WAL SQLite + bounded recent cache</dd>
              </div>
              <div className="flex justify-between items-center py-1.5">
                <dt className="text-kumo-subtle font-medium">RBTA Engine Concurrency</dt>
                <dd className="font-mono text-kumo-default">Non-overlapping Synchronous Ingress</dd>
              </div>
            </dl>
          </div>
        </div>
      </div>
    </>
  );
}
