import { useState } from 'react';
import type { PipelineStageId } from './ReplayPipelineVisualizer';
import type { PipelineTelemetry, ReplayStatus } from '@/api/schemas';
import { Badge } from '@cloudflare/kumo/components/badge';
import { formatNumber } from '@/lib/formatters';
import { FEATURE_LABELS, TERMS, actionLabel } from '@/lib/labels';
import { Copy, Check, Info } from '@phosphor-icons/react';

interface PipelineStageDetailProps {
  activeStage: PipelineStageId;
  telemetry: PipelineTelemetry | undefined;
  status: ReplayStatus | undefined;
}

const STAGE_TITLES: Record<PipelineStageId, string> = {
  DATASET: 'Dataset',
  CANONICAL: 'Standarisasi',
  EVIDENCE: 'Bukti asli',
  RBTA: 'Jendela RBTA',
  META_ALERT: 'Meta-alert',
  FEATURES: '7 fitur',
  ISOLATION_FOREST: 'Isolation Forest',
  DECISION: 'Level',
  OUTPUT_SINK: 'Keluaran',
};

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
            Detail tahap: {STAGE_TITLES[activeStage]}
          </span>
        </div>
        <Badge variant="secondary">
          Data dari server
        </Badge>
      </div>

      {activeStage === 'FEATURES' && (
        <div className="space-y-3">
          <div className="text-xs text-kumo-subtle">
            7 fitur yang dihitung dari meta-alert terakhir yang selesai (#{latestMeta?.meta_id ?? '-'}).
          </div>
          {latestMeta?.seven_features ? (
            <div className="min-w-0">
              <table className="w-full table-fixed text-xs font-mono border-collapse">
                <thead>
                  <tr className="border-b border-kumo-hairline text-kumo-subtle text-[11px]">
                    <th className="py-1.5 px-2 text-left font-medium">Fitur</th>
                    <th className="py-1.5 px-2 text-right font-medium">Nilai</th>
                    <th className="py-1.5 px-2 text-left font-medium">Arti</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-kumo-hairline">
                  {(Object.keys(FEATURE_LABELS) as Array<keyof typeof FEATURE_LABELS>).map((name) => (
                    <tr key={name}>
                      <td className="break-all py-1.5 px-2 text-kumo-default">
                        <span className="font-semibold">{FEATURE_LABELS[name].label}</span>
                        <span className="block text-[10px] text-kumo-subtle">{name}</span>
                      </td>
                      <td className="py-1.5 px-2 text-right font-semibold text-kumo-brand">
                        {latestMeta?.seven_features?.[name]?.toFixed(6) ?? '-'}
                      </td>
                      <td className="py-1.5 px-2 text-kumo-subtle">{FEATURE_LABELS[name].hint}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="py-4 text-center text-xs text-kumo-subtle italic">
              Belum ada meta-alert yang dinilai pada sesi ini.
            </div>
          )}
        </div>
      )}

      {(activeStage === 'ISOLATION_FOREST' || activeStage === 'DECISION') && (
        <div className="space-y-3 font-mono text-xs">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="p-3 rounded bg-kumo-recessed border border-kumo-hairline space-y-1">
              <div className="text-[11px] text-kumo-subtle uppercase">{TERMS.modelVersion}</div>
              <div className="font-semibold text-kumo-default">{latestMeta?.model_version || 'rbta-if-v1'}</div>
              <div className="text-[11px] text-kumo-subtle">Isolation Forest (200 pohon)</div>
              <div className="text-[11px] text-kumo-subtle">Penyeragaman skala fitur (RobustScaler)</div>
            </div>

            <div className="p-3 rounded bg-kumo-recessed border border-kumo-hairline space-y-1">
              <div className="text-[11px] text-kumo-subtle uppercase">Penyesuaian skor ke rentang 0–1</div>
              <div className="flex justify-between">
                <span className="text-kumo-subtle">{TERMS.rawScore}:</span>
                <span className="font-semibold text-kumo-default">{latestMeta?.raw_model_score?.toFixed(6) ?? '-'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-kumo-subtle">{TERMS.anomalyScore}:</span>
                <span className="font-semibold text-kumo-brand">{latestMeta?.anomaly_score?.toFixed(6) ?? '-'}</span>
              </div>
              <div className="text-[11px] text-kumo-subtle">Penyesuaian: min–max (minmax-v1), urutan skor tetap</div>
            </div>

            <div className="p-3 rounded bg-kumo-recessed border border-kumo-hairline space-y-1">
              <div className="text-[11px] text-kumo-subtle uppercase">Batas skor & tindakan</div>
              <div className="flex justify-between">
                <span className="text-kumo-subtle">{TERMS.threshold} (Tukey):</span>
                <span className="font-semibold text-kumo-default">{latestMeta?.threshold_used?.toFixed(6) ?? '-'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-kumo-subtle">{TERMS.margin}:</span>
                <span className={`font-semibold ${(latestMeta?.margin ?? 0) >= 0 ? 'text-red-500' : 'text-kumo-subtle'}`}>
                  {latestMeta?.margin != null ? `${latestMeta.margin >= 0 ? '+' : ''}${latestMeta.margin.toFixed(6)}` : '-'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-kumo-subtle">Tindakan:</span>
                <span className={`font-semibold ${latestMeta?.action === 'ESCALATE' ? 'text-red-500' : 'text-kumo-default'}`}>
                  {actionLabel(latestMeta?.action)?.label ?? latestMeta?.action ?? '-'}
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
              <div className="text-[11px] text-kumo-subtle uppercase">{TERMS.aggregationKey}</div>
              <div className="font-semibold text-kumo-default">(agent_id, rule_group_primary)</div>
              <div className="text-[11px] text-kumo-subtle">Pengelompokan per agen dan kategori aturan, tanpa mencampur agen</div>
            </div>

            <div className="p-3 rounded bg-kumo-recessed border border-kumo-hairline space-y-1">
              <div className="text-[11px] text-kumo-subtle uppercase">Status waktu</div>
              <div className="flex justify-between">
                <span className="text-kumo-subtle">Kelompok terbuka:</span>
                <span className="font-semibold text-kumo-default">{telemetry?.rbta.active_buckets ?? 0}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-kumo-subtle">Agen yang dipantau:</span>
                <span className="font-semibold text-kumo-default">{telemetry?.rbta.active_agents ?? 0}</span>
              </div>
            </div>

            <div className="p-3 rounded bg-kumo-recessed border border-kumo-hairline space-y-1">
              <div className="text-[11px] text-kumo-subtle uppercase">Riwayat kelompok</div>
              <div className="flex justify-between">
                <span className="text-kumo-subtle">Meta-alert selesai:</span>
                <span className="font-semibold text-kumo-brand">{formatNumber(telemetry?.rbta.finalized_meta_alerts ?? 0)}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-kumo-subtle">Pengurangan alert:</span>
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
              Berkas: <code className="text-kumo-default bg-kumo-recessed px-1.5 py-0.5 rounded">data/runtime/telegram_escalate_payloads.txt</code>
            </span>
            <span className="text-kumo-subtle">
              Total pesan 'perlu dicek segera': <span className="font-semibold text-kumo-brand">{telemetry?.output.telegram_deferred_count ?? 0}</span>
            </span>
          </div>

          {telemetry?.output.latest_payload ? (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-semibold text-kumo-subtle uppercase">Pesan Telegram terakhir yang belum dikirim (JSON)</span>
                <button
                  type="button"
                  onClick={() => handleCopy(JSON.stringify(telemetry.output.latest_payload, null, 2))}
                  className="flex items-center gap-1 text-xs font-mono text-kumo-brand hover:underline"
                >
                  {copied ? <Check size={12} /> : <Copy size={12} />}
                  <span>{copied ? 'Tersalin' : 'Salin JSON'}</span>
                </button>
              </div>
              <pre className="whitespace-pre-wrap break-all p-3 rounded bg-kumo-recessed border border-kumo-hairline font-mono text-[11px] text-kumo-default">
                {JSON.stringify(telemetry.output.latest_payload, null, 2)}
              </pre>
            </div>
          ) : (
            <div className="py-4 text-center text-xs text-kumo-subtle font-mono italic">
              Belum ada alert yang perlu dicek segera pada sesi replay ini.
            </div>
          )}
        </div>
      )}

      {(activeStage === 'DATASET' || activeStage === 'CANONICAL' || activeStage === 'EVIDENCE' || activeStage === 'META_ALERT') && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-xs">
          <div className="p-3 rounded bg-kumo-recessed border border-kumo-hairline space-y-1">
            <div className="text-[11px] text-kumo-subtle uppercase">Penerimaan & asal data</div>
            <div className="flex justify-between">
              <span className="text-kumo-subtle">Dataset:</span>
              <span className="font-semibold text-kumo-default truncate max-w-[200px]">{status?.current_dataset || status?.dataset || '-'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-kumo-subtle">Waktu kejadian:</span>
              <span className="text-kumo-default">{status?.current_event_time || '-'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-kumo-subtle">ID sesi replay:</span>
              <span className="text-kumo-default truncate max-w-[200px]">{status?.run_id || '-'}</span>
            </div>
          </div>

          <div className="p-3 rounded bg-kumo-recessed border border-kumo-hairline space-y-1">
            <div className="text-[11px] text-kumo-subtle uppercase">Alert terakhir yang diproses</div>
            <div className="flex justify-between">
              <span className="text-kumo-subtle">ID alert:</span>
              <span className="text-kumo-default">{telemetry?.raw.last_alert?.alert_id as string || '-'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-kumo-subtle">Level rule:</span>
              <span className="text-kumo-default">{telemetry?.raw.last_alert?.level as number || '-'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-kumo-subtle">Kategori aturan:</span>
              <span className="text-kumo-default">{telemetry?.raw.last_alert?.rule_group as string || '-'}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
