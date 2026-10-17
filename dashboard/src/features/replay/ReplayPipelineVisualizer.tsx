import React, { useEffect, useRef, useState } from 'react';
import type { ReplayStatus, PipelineTelemetry } from '@/api/schemas';
import { formatNumber } from '@/lib/formatters';
import { decisionLabel } from '@/lib/labels';
import {
  Database,
  ArrowsSplit,
  HardDrives,
  ClockAfternoon,
  Stack,
  ChartBarHorizontal,
  TreeStructure,
  Scales,
  PaperPlaneRight,
  CheckCircle,
  WarningCircle,
  PauseCircle,
  PlayCircle,
} from '@phosphor-icons/react';

export type PipelineStageId =
  | 'DATASET'
  | 'CANONICAL'
  | 'EVIDENCE'
  | 'RBTA'
  | 'META_ALERT'
  | 'FEATURES'
  | 'ISOLATION_FOREST'
  | 'DECISION'
  | 'OUTPUT_SINK';

interface ReplayPipelineVisualizerProps {
  status: ReplayStatus | undefined;
  telemetry: PipelineTelemetry | undefined;
  activeStage: PipelineStageId | null;
  onSelectStage: (stage: PipelineStageId) => void;
}

export function ReplayPipelineVisualizer({
  status,
  telemetry,
  activeStage,
  onSelectStage,
}: ReplayPipelineVisualizerProps) {
  const isRunning = status?.status === 'RUNNING';
  const isPaused = status?.status === 'PAUSED';
  const isCompleted = status?.status === 'COMPLETED';
  const isError = status?.status === 'ERROR';

  const rawProcessed = telemetry?.raw.processed ?? status?.processed_count ?? 0;
  const rawTotal = status?.total_count ?? 0;
  const evidenceCount = telemetry?.raw.evidence_count ?? rawProcessed;
  const activeBuckets = telemetry?.rbta.active_buckets ?? 0;
  const finalizedCount = telemetry?.rbta.finalized_meta_alerts ?? 0;
  const activeAgents = telemetry?.rbta.active_agents ?? 0;
  const latestMeta = telemetry?.latest_meta_alert;
  const telegramCount = telemetry?.output.telegram_deferred_count ?? 0;
  const [processing, setProcessing] = useState<Set<PipelineStageId>>(new Set());
  const previous = useRef({ rawProcessed, evidenceCount, finalizedCount, telegramCount });
  useEffect(() => {
    if (!isRunning) { setProcessing(new Set()); previous.current = { rawProcessed, evidenceCount, finalizedCount, telegramCount }; return; }
    const changed = new Set<PipelineStageId>(); const prior = previous.current;
    if (rawProcessed > prior.rawProcessed) ['DATASET', 'CANONICAL', 'EVIDENCE', 'RBTA'].forEach((id) => changed.add(id as PipelineStageId));
    if (evidenceCount > prior.evidenceCount) changed.add('EVIDENCE');
    if (finalizedCount > prior.finalizedCount) ['META_ALERT', 'FEATURES', 'ISOLATION_FOREST', 'DECISION'].forEach((id) => changed.add(id as PipelineStageId));
    if (telegramCount > prior.telegramCount) changed.add('OUTPUT_SINK');
    previous.current = { rawProcessed, evidenceCount, finalizedCount, telegramCount };
    if (changed.size) { setProcessing(changed); const timer = window.setTimeout(() => setProcessing(new Set()), 600); return () => window.clearTimeout(timer); }
  }, [isRunning, rawProcessed, evidenceCount, finalizedCount, telegramCount]);

  const phases = [
    {
      phaseName: 'Tahap 1: Penerimaan & penyimpanan alert',
      stages: [
        {
          id: 'DATASET' as PipelineStageId,
          num: '01',
          title: '1. Dataset',
          sublabel: status?.dataset_mode === 'all' ? 'Semua dataset' : (status?.dataset ? 'Satu file .jsonl' : 'Sumber historis'),
          icon: Database,
          metric: `${formatNumber(rawProcessed)} / ${formatNumber(rawTotal)}`,
          metricLabel: 'Diproses',
        },
        {
          id: 'CANONICAL' as PipelineStageId,
          num: '02',
          title: '2. Standarisasi',
          sublabel: 'Data terstandar',
          icon: ArrowsSplit,
          metric: `${formatNumber(rawProcessed)} alert`,
          metricLabel: 'Tervalidasi',
        },
        {
          id: 'EVIDENCE' as PipelineStageId,
          num: '03',
          title: '3. Bukti asli',
          sublabel: 'Disimpan di SQLite',
          icon: HardDrives,
          metric: `${formatNumber(evidenceCount)} baris`,
          metricLabel: 'Terindeks',
        },
      ],
    },
    {
      phaseName: 'Tahap 2: Pengelompokan waktu & fitur',
      stages: [
        {
          id: 'RBTA' as PipelineStageId,
          num: '04',
          title: '4. Jendela RBTA',
          sublabel: 'Pengelompokan adaptif',
          icon: ClockAfternoon,
          metric: `${activeBuckets} terbuka / ${activeAgents} agen`,
          metricLabel: 'Aktif',
        },
        {
          id: 'META_ALERT' as PipelineStageId,
          num: '05',
          title: '5. Meta-alert',
          sublabel: 'Kelompok alert',
          icon: Stack,
          metric: `${formatNumber(finalizedCount)} selesai`,
          metricLabel: 'Kelompok',
        },
        {
          id: 'FEATURES' as PipelineStageId,
          num: '06',
          title: '6. 7 fitur',
          sublabel: 'Vektor 7 fitur',
          icon: ChartBarHorizontal,
          metric: `Keparahan maks.: ${latestMeta?.max_severity ?? 0}/15`,
          metricLabel: 'Diekstrak',
        },
      ],
    },
    {
      phaseName: 'Tahap 3: Isolation Forest & pengiriman',
      stages: [
        {
          id: 'ISOLATION_FOREST' as PipelineStageId,
          num: '07',
          title: '7. IsoForest',
          sublabel: '200 pohon',
          icon: TreeStructure,
          metric: latestMeta?.anomaly_score !== undefined ? latestMeta.anomaly_score.toFixed(4) : '-',
          metricLabel: 'Skor',
        },
        {
          id: 'DECISION' as PipelineStageId,
          num: '08',
          title: '8. Level',
          sublabel: 'Batas Tukey + matriks keputusan',
          icon: Scales,
          metric: decisionLabel(latestMeta?.decision ?? 'NOISE')?.label ?? latestMeta?.decision ?? '-',
          metricLabel: 'Level',
        },
        {
          id: 'OUTPUT_SINK' as PipelineStageId,
          num: '09',
          title: '9. Keluaran',
          sublabel: 'Telegram (belum aktif)',
          icon: PaperPlaneRight,
          metric: `${telegramCount} antre`,
          metricLabel: 'Pesan',
        },
      ],
    },
  ];

  return (
    <div className="rounded-xl border border-kumo-hairline bg-kumo-canvas p-6 shadow-xs space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-kumo-hairline">
        <div className="space-y-1">
          <div className="flex items-center gap-3">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-kumo-strong">
              Alur pemrosesan
            </h2>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded border border-kumo-hairline bg-kumo-recessed text-kumo-subtle">
              9 TAHAP
            </span>
          </div>
          <p className="text-xs text-kumo-subtle">
            Alur visual: alert masuk, validasi, pengelompokan, 7 fitur, lalu skor keanehan. Klik tahap untuk melihat detail
          </p>
        </div>

        <div className="flex items-center gap-2 font-mono text-xs">
          {isRunning && (
            <span className="flex items-center gap-1.5 px-3 py-1 rounded-md bg-kumo-recessed text-kumo-strong border border-kumo-hairline font-semibold">
              <PlayCircle size={14} weight="fill" className="text-emerald-500 animate-pulse" />
              <span>Berjalan</span>
            </span>
          )}
          {isPaused && (
            <span className="flex items-center gap-1.5 px-3 py-1 rounded-md bg-kumo-recessed text-kumo-strong border border-kumo-hairline font-semibold">
              <PauseCircle size={14} weight="fill" className="text-amber-500" />
              <span>Dijeda</span>
            </span>
          )}
          {isCompleted && (
            <span className="flex items-center gap-1.5 px-3 py-1 rounded-md bg-kumo-recessed text-kumo-strong border border-kumo-hairline font-semibold">
              <CheckCircle size={14} weight="fill" className="text-emerald-500" />
              <span>Selesai</span>
            </span>
          )}
          {isError && (
            <span className="flex items-center gap-1.5 px-3 py-1 rounded-md bg-kumo-recessed text-rose-500 border border-rose-500/30 font-semibold">
              <WarningCircle size={14} weight="fill" />
              <span>Gagal</span>
            </span>
          )}
          {!isRunning && !isPaused && !isCompleted && !isError && (
            <span className="flex items-center gap-1.5 px-3 py-1 rounded-md bg-kumo-recessed text-kumo-subtle border border-kumo-hairline">
              <span>Belum berjalan</span>
            </span>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {phases.map((phase, pIdx) => (
          <div
            key={phase.phaseName}
            className="p-4 rounded-lg border border-kumo-hairline/80 bg-kumo-recessed/20 space-y-3 relative"
          >
            <div className="flex items-center justify-between px-1">
              <span className="text-[10px] font-bold text-kumo-subtle tracking-wider uppercase">
                {phase.phaseName}
              </span>
              <span className="text-[10px] font-mono text-kumo-subtle">
                Tahap {pIdx * 3 + 1}–{pIdx * 3 + 3}
              </span>
            </div>

            <div className="space-y-2.5">
              {phase.stages.map((st, sIdx) => {
                const isSelected = activeStage === st.id;
                const isProcessing = processing.has(st.id);
                const Icon = st.icon;

                return (
                  <React.Fragment key={st.id}>
                    <button
                      type="button"
                      onClick={() => onSelectStage(st.id)}
                      className={`w-full text-left p-3.5 rounded-lg border transition-all duration-150 relative cursor-pointer ${
                        isSelected
                          ? 'bg-kumo-canvas border-kumo-strong shadow-sm ring-1 ring-kumo-strong'
                          : 'bg-kumo-canvas/80 hover:bg-kumo-canvas border-kumo-hairline hover:border-kumo-line shadow-2xs'
                      }`}
                      aria-pressed={isSelected}
                    >
                      <div className="flex items-center justify-between gap-3">
                        <div className="flex items-center gap-3 min-w-0">
                          <div className={`w-8 h-8 rounded-md border flex items-center justify-center shrink-0 ${
                            isSelected
                              ? 'bg-kumo-recessed border-kumo-strong text-kumo-strong'
                              : 'bg-kumo-recessed/60 border-kumo-hairline text-kumo-subtle'
                          }`}>
                            <Icon size={16} weight={isSelected ? 'duotone' : 'regular'} />
                          </div>
                          <div className="min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="text-xs font-semibold text-kumo-strong truncate">
                                {st.title}
                              </span>
                            </div>
                            <div className="text-[11px] text-kumo-subtle truncate">
                              {st.sublabel}
                            </div>
                          </div>
                        </div>

                        <div className="text-right shrink-0">
                          <div className="font-mono text-xs font-bold text-kumo-strong">
                            {st.metric}
                          </div>
                          <div className="text-[10px] text-kumo-subtle">
                            {st.metricLabel}
                          </div>
                        </div>
                      </div>

                      {isProcessing && (
                        <div
                          className="absolute top-2 right-2 w-1.5 h-1.5 rounded-full bg-blue-500 motion-safe:animate-ping"
                          aria-hidden="true"
                        />
                      )}
                    </button>

                    {sIdx < phase.stages.length - 1 && (
                      <div className="flex justify-center text-kumo-hairline py-0.5">
                        <span className="text-[10px] font-mono text-kumo-subtle flex items-center gap-1">
                          ↓ <span className="text-[9px] uppercase tracking-wider">ALUR</span>
                        </span>
                      </div>
                    )}
                  </React.Fragment>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
