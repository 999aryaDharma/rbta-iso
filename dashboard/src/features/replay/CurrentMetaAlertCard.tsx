import type { PipelineLatestMetaAlert } from '@/api/schemas';
import { DecisionBadge } from '@/components/shared/DecisionBadge';
import { Badge } from '@cloudflare/kumo/components/badge';
import { formatNumber } from '@/lib/formatters';
import { Warning } from '@phosphor-icons/react';

interface CurrentMetaAlertCardProps {
  latestMeta: PipelineLatestMetaAlert | null | undefined;
  rawProcessed: number;
  metaFinalized: number;
  decisionCounts?: Record<string, number>;
}

export function CurrentMetaAlertCard({
  latestMeta,
  rawProcessed,
  metaFinalized,
  decisionCounts = {},
}: CurrentMetaAlertCardProps) {
  const reductionRate = rawProcessed > 0 && metaFinalized > 0
    ? Math.max(0, ((rawProcessed - metaFinalized) / rawProcessed) * 100)
    : 0;

  const score = latestMeta?.anomaly_score ?? 0;
  const threshold = latestMeta?.threshold_used ?? 0;
  const margin = latestMeta?.margin ?? (score - threshold);

  return (
    <div className="rounded-xl border border-kumo-hairline bg-kumo-canvas p-6 shadow-xs space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-4 pb-3 border-b border-kumo-hairline">
        <div className="flex items-center gap-3">
          <div className="text-xs font-semibold uppercase tracking-wider text-kumo-strong">
            Meta-alert terbaru
          </div>
          {latestMeta ? (
            <Badge variant="secondary">
              #{latestMeta.meta_id}
            </Badge>
          ) : (
            <span className="text-xs text-kumo-subtle italic">Menunggu kelompok alert pertama selesai diproses.</span>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-4 text-xs font-mono">
          <div className="flex items-center gap-1.5 text-kumo-subtle">
            <span>Pengurangan alert:</span>
            <span className="font-semibold text-kumo-strong">{reductionRate.toFixed(1)}%</span>
            <span className="text-[11px] text-kumo-subtle">({formatNumber(rawProcessed)} alert → {formatNumber(metaFinalized)} kelompok)</span>
          </div>

          <div className="flex items-center gap-3 pl-3 border-l border-kumo-hairline">
            <span className="text-rose-500 font-semibold flex items-center gap-1">
              <Warning size={13} /> Perlu dicek segera: {decisionCounts.ESCALATE || 0}
            </span>
            <span className="text-kumo-subtle flex items-center gap-1">
              Tidak ditampilkan di antrean: {decisionCounts.SUPPRESS || 0}
            </span>
            {decisionCounts.DAILY_DIGEST ? (
              <span className="text-kumo-subtle flex items-center gap-1">
                Ringkasan harian: {decisionCounts.DAILY_DIGEST}
              </span>
            ) : null}
          </div>
        </div>
      </div>

      {latestMeta ? (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 pt-1">
          <div className="space-y-1.5">
            <div className="text-[11px] text-kumo-subtle uppercase tracking-wider font-semibold">Sumber alert</div>
            <div className="font-mono text-xs font-semibold text-kumo-strong truncate">
              {latestMeta.agent_name} ({latestMeta.agent_id})
            </div>
            <div className="font-mono text-xs text-kumo-subtle">
              Kategori aturan: <span className="text-kumo-default font-medium">{latestMeta.rule_group_primary}</span>
            </div>
          </div>

          <div className="space-y-1.5">
            <div className="text-[11px] text-kumo-subtle uppercase tracking-wider font-semibold">Ringkasan kelompok</div>
            <div className="text-xs text-kumo-default">
              <span className="font-mono font-bold text-kumo-strong">{latestMeta.alert_count}</span> alert digabungkan
            </div>
            <div className="text-xs text-kumo-subtle">
              Keparahan maks.: <span className="font-mono font-semibold text-kumo-default">{latestMeta.max_severity}</span> / 15
            </div>
          </div>

          {/* Perbandingan angka tanpa mengubah rentang aslinya */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-kumo-subtle uppercase tracking-wider font-semibold">Skor dan batas</span>
              <span className="font-mono font-bold text-kumo-strong">
                {margin >= 0 ? `+${margin.toFixed(4)}` : margin.toFixed(4)}
              </span>
            </div>
            <div className="flex justify-between text-[10px] font-mono text-kumo-subtle">
              <span>Skor keanehan: {score.toFixed(4)}</span>
              <span>Batas skor: {threshold.toFixed(4)}</span>
            </div>
            <p className="text-[10px] leading-4 text-kumo-subtle">{margin >= 0 ? 'Skor berada di atas batas.' : 'Skor berada di bawah batas.'} Angka asli ditampilkan tanpa dipotong.</p>
          </div>

          {/* Level dan tindakan adalah dua hal berbeda */}
          <div className="space-y-1.5 flex flex-col justify-center">
            <div className="text-[11px] text-kumo-subtle uppercase tracking-wider font-semibold">Hasil dan tindakan</div>
            <div className="flex items-center gap-2">
              {latestMeta.decision && (
                <DecisionBadge decision={latestMeta.decision} action={latestMeta.action || 'SUPPRESS'} />
              )}
            </div>
            <p className="text-[10px] leading-4 text-kumo-subtle">Tindakan membantu urutan triase; ini bukan bukti bahwa terjadi serangan.</p>
          </div>
        </div>
      ) : (
        <div className="py-6 text-center text-xs text-kumo-subtle font-mono">
          Data sedang diproses. Meta-alert akan muncul setelah satu kelompok alert selesai.
        </div>
      )}
    </div>
  );
}
