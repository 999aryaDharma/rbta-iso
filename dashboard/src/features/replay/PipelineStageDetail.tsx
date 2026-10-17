import { useState } from 'react';
import type { PipelineStageId } from './ReplayPipelineVisualizer';
import type { PipelineTelemetry, ReplayStatus } from '@/api/schemas';
import { Badge } from '@cloudflare/kumo/components/badge';
import { formatNumber } from '@/lib/formatters';
import { Copy, Check, Info } from '@phosphor-icons/react';

interface PipelineStageDetailProps {
  activeStage: PipelineStageId;
  telemetry: PipelineTelemetry | undefined;
  status: ReplayStatus | undefined;
}

export function PipelineStageDetail({
  activeStage,
  telemetry,
  status,
}: PipelineStageDetailProps) {
  const [copied, setCopied] = useState(false);
  const latestMeta = telemetry?.latest_meta_alert;

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="rounded-xl border border-kumo-hairline bg-kumo-canvas p-6 shadow-xs space-y-4">
      <div className="flex items-center justify-between pb-3 border-b border-kumo-hairline">
        <div className="flex items-center gap-2.5">
          <div className="w-6 h-6 rounded-md border border-kumo-hairline bg-kumo-recessed flex items-center justify-center text-kumo-strong">
            <Info size={14} />
          </div>
          <span className="text-xs font-semibold uppercase tracking-wider text-kumo-strong">
            Stage Inspection: {activeStage.replace('_', ' ')}
          </span>
        </div>
        <Badge variant="secondary">
          Authoritative Backend Telemetry
        </Badge>
      </div>

      {activeStage === 'FEATURES' && (
        <div className="space-y-3">
          <div className="text-xs text-kumo-subtle">
            Exact Seven-Dimensional Numerical Feature Vector extracted from the latest finalized MetaAlert (#{latestMeta?.meta_id ?? '-'}).
          </div>
          {latestMeta?.seven_features ? (
            <div className="min-w-0">
              <table className="w-full table-fixed text-xs font-mono border-collapse">
                <thead>
                  <tr className="border-b border-kumo-hairline text-kumo-subtle text-[11px]">
                    <th className="py-1.5 px-2 text-left font-medium">Feature Key</th>
                    <th className="py-1.5 px-2 text-right font-medium">Float Value</th>
                    <th className="py-1.5 px-2 text-left font-medium">Research Semantic</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-kumo-hairline">
                  <tr>
                    <td className="break-all py-1.5 px-2 font-semibold text-kumo-default">max_severity</td>
                    <td className="py-1.5 px-2 text-right font-semibold text-kumo-brand">
                      {latestMeta.seven_features['max_severity']?.toFixed(6) ?? '-'}
                    </td>
                    <td className="py-1.5 px-2 text-kumo-subtle">Highest Wazuh rule level observed in cluster (1–15)</td>
                  </tr>
                  <tr>
                    <td className="break-all py-1.5 px-2 font-semibold text-kumo-default">mitre_tactic_count</td>
                    <td className="py-1.5 px-2 text-right font-semibold text-kumo-brand">
                      {latestMeta.seven_features['mitre_tactic_count']?.toFixed(6) ?? '-'}
                    </td>
                    <td className="py-1.5 px-2 text-kumo-subtle">Distinct MITRE ATT&CK tactics involved</td>
                  </tr>
                  <tr>
                    <td className="break-all py-1.5 px-2 font-semibold text-kumo-default">critical_mitre_tactic_present</td>
                    <td className="py-1.5 px-2 text-right font-semibold text-kumo-brand">
                      {latestMeta.seven_features['critical_mitre_tactic_present']?.toFixed(6) ?? '-'}
                    </td>
                    <td className="py-1.5 px-2 text-kumo-subtle">Binary flag (1.0 = Exfiltration / Privilege Escalation / Impact present)</td>
                  </tr>
                  <tr>
                    <td className="break-all py-1.5 px-2 font-semibold text-kumo-default">alert_count_log</td>
                    <td className="py-1.5 px-2 text-right font-semibold text-kumo-brand">
                      {latestMeta.seven_features['alert_count_log']?.toFixed(6) ?? '-'}
                    </td>
                    <td className="py-1.5 px-2 text-kumo-subtle">Natural logarithm of cluster size: ln(1 + count)</td>
                  </tr>
                  <tr>
                    <td className="break-all py-1.5 px-2 font-semibold text-kumo-default">rule_diversity_shannon</td>
                    <td className="py-1.5 px-2 text-right font-semibold text-kumo-brand">
                      {latestMeta.seven_features['rule_diversity_shannon']?.toFixed(6) ?? '-'}
                    </td>
                    <td className="py-1.5 px-2 text-kumo-subtle">Shannon entropy of rule_id distribution in bucket</td>
                  </tr>
                  <tr>
                    <td className="break-all py-1.5 px-2 font-semibold text-kumo-default">severity_dispersion</td>
                    <td className="py-1.5 px-2 text-right font-semibold text-kumo-brand">
                      {latestMeta.seven_features['severity_dispersion']?.toFixed(6) ?? '-'}
                    </td>
                    <td className="py-1.5 px-2 text-kumo-subtle">Normalized standard deviation of alert severities</td>
                  </tr>
                  <tr>
                    <td className="break-all py-1.5 px-2 font-semibold text-kumo-default">agent_criticality</td>
                    <td className="py-1.5 px-2 text-right font-semibold text-kumo-brand">
                      {latestMeta.seven_features['agent_criticality']?.toFixed(6) ?? '-'}
                    </td>
                    <td className="py-1.5 px-2 text-kumo-subtle">Asset criticality tier of monitored endpoint (1–3)</td>
                  </tr>
                </tbody>
              </table>
            </div>
          ) : (
            <div className="py-4 text-center text-xs text-kumo-subtle italic">
              No MetaAlert scored yet in current run.
            </div>
          )}
        </div>
      )}

      {(activeStage === 'ISOLATION_FOREST' || activeStage === 'DECISION') && (
        <div className="space-y-3 font-mono text-xs">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="p-3 rounded bg-kumo-recessed border border-kumo-hairline space-y-1">
              <div className="text-[11px] text-kumo-subtle uppercase">Model Architecture</div>
              <div className="font-semibold text-kumo-default">{latestMeta?.model_version || 'rbta-if-v1'}</div>
              <div className="text-[11px] text-kumo-subtle">Isolation Forest (200 trees, contamination="auto")</div>
              <div className="text-[11px] text-kumo-subtle">Scaler: RobustScaler (IQR normalization)</div>
            </div>

            <div className="p-3 rounded bg-kumo-recessed border border-kumo-hairline space-y-1">
              <div className="text-[11px] text-kumo-subtle uppercase">Score Calibration</div>
              <div className="flex justify-between">
                <span className="text-kumo-subtle">Raw Model Score:</span>
                <span className="font-semibold text-kumo-default">{latestMeta?.raw_model_score?.toFixed(6) ?? '-'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-kumo-subtle">Calibrated Anomaly:</span>
                <span className="font-semibold text-kumo-brand">{latestMeta?.anomaly_score?.toFixed(6) ?? '-'}</span>
              </div>
              <div className="text-[11px] text-kumo-subtle">Calibration: MinMax-v1 strictly monotonically mapped</div>
            </div>

            <div className="p-3 rounded bg-kumo-recessed border border-kumo-hairline space-y-1">
              <div className="text-[11px] text-kumo-subtle uppercase">Level Threshold</div>
              <div className="flex justify-between">
                <span className="text-kumo-subtle">Tukey Threshold:</span>
                <span className="font-semibold text-kumo-default">{latestMeta?.threshold_used?.toFixed(6) ?? '-'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-kumo-subtle">Margin (Score - Thresh):</span>
                <span className={`font-semibold ${(latestMeta?.margin ?? 0) >= 0 ? 'text-red-500' : 'text-kumo-subtle'}`}>
                  {latestMeta?.margin != null ? `${latestMeta.margin >= 0 ? '+' : ''}${latestMeta.margin.toFixed(6)}` : '-'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-kumo-subtle">Action:</span>
                <span className={`font-semibold ${latestMeta?.action === 'ESCALATE' ? 'text-red-500' : 'text-kumo-default'}`}>
                  {latestMeta?.action ?? '-'}
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {activeStage === 'RBTA' && (
        <div className="space-y-3 font-mono text-xs">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="p-3 rounded bg-kumo-recessed border border-kumo-hairline space-y-1">
              <div className="text-[11px] text-kumo-subtle uppercase">Aggregation Key</div>
              <div className="font-semibold text-kumo-default">(agent_id, rule_group_primary)</div>
              <div className="text-[11px] text-kumo-subtle">Single-bucket deterministic clustering without cross-agent pollution</div>
            </div>

            <div className="p-3 rounded bg-kumo-recessed border border-kumo-hairline space-y-1">
              <div className="text-[11px] text-kumo-subtle uppercase">Temporal State</div>
              <div className="flex justify-between">
                <span className="text-kumo-subtle">Active Buckets:</span>
                <span className="font-semibold text-kumo-default">{telemetry?.rbta.active_buckets ?? 0}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-kumo-subtle">Active Monitored Agents:</span>
                <span className="font-semibold text-kumo-default">{telemetry?.rbta.active_agents ?? 0}</span>
              </div>
            </div>

            <div className="p-3 rounded bg-kumo-recessed border border-kumo-hairline space-y-1">
              <div className="text-[11px] text-kumo-subtle uppercase">Cluster History</div>
              <div className="flex justify-between">
                <span className="text-kumo-subtle">Finalized MetaAlerts:</span>
                <span className="font-semibold text-kumo-brand">{formatNumber(telemetry?.rbta.finalized_meta_alerts ?? 0)}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-kumo-subtle">Reduction Ratio:</span>
                <span className="font-semibold text-kumo-default">
                  {telemetry?.raw.processed && telemetry?.rbta.finalized_meta_alerts
                    ? `${(((telemetry.raw.processed - telemetry.rbta.finalized_meta_alerts) / telemetry.raw.processed) * 100).toFixed(1)}%`
                    : '0%'}
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {activeStage === 'OUTPUT_SINK' && (
        <div className="space-y-3">
          <div className="flex items-center justify-between text-xs font-mono">
            <span className="text-kumo-subtle">
              File: <code className="text-kumo-default bg-kumo-recessed px-1.5 py-0.5 rounded">data/runtime/telegram_escalate_payloads.txt</code>
            </span>
            <span className="text-kumo-subtle">
              Total ESCALATE Payloads: <span className="font-semibold text-kumo-brand">{telemetry?.output.telegram_deferred_count ?? 0}</span>
            </span>
          </div>

          {telemetry?.output.latest_payload ? (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-semibold text-kumo-subtle uppercase">Latest Deferred Telegram Payload (JSON)</span>
                <button
                  type="button"
                  onClick={() => handleCopy(JSON.stringify(telemetry.output.latest_payload, null, 2))}
                  className="flex items-center gap-1 text-xs font-mono text-kumo-brand hover:underline"
                >
                  {copied ? <Check size={12} /> : <Copy size={12} />}
                  <span>{copied ? 'Copied' : 'Copy JSON'}</span>
                </button>
              </div>
              <pre className="whitespace-pre-wrap break-all p-3 rounded bg-kumo-recessed border border-kumo-hairline font-mono text-[11px] text-kumo-default">
                {JSON.stringify(telemetry.output.latest_payload, null, 2)}
              </pre>
            </div>
          ) : (
            <div className="py-4 text-center text-xs text-kumo-subtle font-mono italic">
              No ESCALATE actions triggered yet in this replay session.
            </div>
          )}
        </div>
      )}

      {(activeStage === 'DATASET' || activeStage === 'CANONICAL' || activeStage === 'EVIDENCE' || activeStage === 'META_ALERT') && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-xs">
          <div className="p-3 rounded bg-kumo-recessed border border-kumo-hairline space-y-1">
            <div className="text-[11px] text-kumo-subtle uppercase">Ingress & Provenance</div>
            <div className="flex justify-between">
              <span className="text-kumo-subtle">Dataset:</span>
              <span className="font-semibold text-kumo-default truncate max-w-[200px]">{status?.current_dataset || status?.dataset || '-'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-kumo-subtle">Event Time:</span>
              <span className="text-kumo-default">{status?.current_event_time || '-'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-kumo-subtle">Run ID:</span>
              <span className="text-kumo-default truncate max-w-[200px]">{status?.run_id || '-'}</span>
            </div>
          </div>

          <div className="p-3 rounded bg-kumo-recessed border border-kumo-hairline space-y-1">
            <div className="text-[11px] text-kumo-subtle uppercase">Last Processed Raw Alert</div>
            <div className="flex justify-between">
              <span className="text-kumo-subtle">Alert ID:</span>
              <span className="text-kumo-default">{telemetry?.raw.last_alert?.alert_id as string || '-'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-kumo-subtle">Rule Level:</span>
              <span className="text-kumo-default">{telemetry?.raw.last_alert?.level as number || '-'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-kumo-subtle">Group:</span>
              <span className="text-kumo-default">{telemetry?.raw.last_alert?.rule_group as string || '-'}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
