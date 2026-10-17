import React, { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { usePollingQuery } from '@/hooks/usePolling';
import {
  fetchReplayDatasets,
  fetchReplayStatus,
  startReplay,
  pauseReplay,
  resumeReplay,
  stopReplay,
  resetReplay,
  fetchEvaluationStatus,
  startEvaluation,
  cancelEvaluation,
  downloadEvaluationArtifact,
  fetchDatasetCatalogStatus,
  refreshDatasetCatalog,
} from '@/api/replay';
import { PageHeader } from '@/components/shared/PageHeader';
import { MetricCard } from '@/components/shared/MetricCard';
import { DialogRoot, Dialog, DialogTitle, DialogDescription, DialogClose } from '@cloudflare/kumo/components/dialog';
import { Banner } from '@cloudflare/kumo/components/banner';
import { Button } from '@cloudflare/kumo/components/button';
import { formatNumber, formatDuration } from '@/lib/formatters';
import { TERMS } from '@/lib/labels';
import { Play, Pause, Stop, ArrowClockwise, FastForward, ArrowRight, CaretDown } from '@phosphor-icons/react';
import { ReplayPipelineVisualizer, type PipelineStageId } from './ReplayPipelineVisualizer';
import { CurrentMetaAlertCard } from './CurrentMetaAlertCard';
import { PipelineStageDetail } from './PipelineStageDetail';
import { ProcessingTrace } from './ProcessingTrace';
import { DeferredTelegramOutbox } from './DeferredTelegramOutbox';
import { LiveEvaluationPanel } from '@/features/demo/LiveEvaluationPanel';
import { PostReplayEvaluation } from '@/features/demo/PostReplayEvaluation';
import { DatasetCatalogPanel } from '@/features/demo/DatasetCatalogPanel';

function ZoneSection({
  zoneId,
  index,
  title,
  description,
  children,
}: {
  zoneId: string;
  index: string;
  title: string;
  description: string;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(true);
  return (
    <section aria-label={title} className="rounded-xl border border-kumo-hairline bg-kumo-canvas/40">
      <button
        type="button"
        aria-expanded={open}
        aria-controls={`${zoneId}-body`}
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center justify-between gap-4 px-6 py-4 text-left cursor-pointer"
      >
        <span>
          <span className="block text-[11px] font-semibold uppercase tracking-wider text-kumo-subtle">{index}</span>
          <span className="block text-sm font-bold text-kumo-strong">{title}</span>
          <span className="block text-xs text-kumo-subtle mt-0.5">{description}</span>
        </span>
        <CaretDown size={16} className={`shrink-0 text-kumo-subtle transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && (
        <div id={`${zoneId}-body`} className="px-6 pb-6 space-y-8">
          {children}
        </div>
      )}
    </section>
  );
}

export function ReplayPage() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const { data: datasetsData } = useQuery({ queryKey: ['replay-datasets'], queryFn: fetchReplayDatasets });
  const { data: status } = usePollingQuery(['replay'], fetchReplayStatus, 1000);
  const { data: evaluation } = usePollingQuery(['replay-evaluation'], fetchEvaluationStatus, 1200);
  const { data: catalogStatus } = usePollingQuery(['dataset-catalog'], fetchDatasetCatalogStatus, 1500);

  const [selectedDataset, setSelectedDataset] = useState<string>('');
  const [speed, setSpeed] = useState<'1' | '10' | '100' | 'MAX'>('MAX');
  const [isLoading, setIsLoading] = useState(false);
  const [showResetConfirm, setShowResetConfirm] = useState(false);
  const [activeStage, setActiveStage] = useState<PipelineStageId | null>(null);

  // Pilih dataset default setelah daftar dimuat
  React.useEffect(() => {
    if (datasetsData?.items && datasetsData.items.length > 0 && !selectedDataset) {
      setSelectedDataset(datasetsData.items[0].name);
    }
  }, [datasetsData, selectedDataset]);

  // Sinkronkan run_id ke URL saat replay aktif
  React.useEffect(() => {
    if (status?.run_id && searchParams.get('run_id') !== status.run_id) {
      const params = new URLSearchParams(searchParams);
      params.set('run_id', status.run_id);
      setSearchParams(params, { replace: true });
    }
  }, [status?.run_id, searchParams, setSearchParams]);

  React.useEffect(() => {
    if (catalogStatus?.completed_at_utc) {
      void queryClient.invalidateQueries({ queryKey: ['replay-datasets'] });
    }
  }, [catalogStatus?.completed_at_utc, queryClient]);

  const handleAction = async (action: () => Promise<any>) => {
    setIsLoading(true);
    try {
      await action();
      await queryClient.invalidateQueries({ queryKey: ['replay'] });
      await queryClient.invalidateQueries({ queryKey: ['telegram-payloads'] });
      await queryClient.invalidateQueries({ queryKey: ['replay-evaluation'] });
    } finally {
      setIsLoading(false);
    }
  };

  const handleConfirmReset = async () => {
    setShowResetConfirm(false);
    await handleAction(resetReplay);
    const params = new URLSearchParams(searchParams);
    params.delete('run_id');
    setSearchParams(params, { replace: true });
  };

  const isIdle = !status || status.status === 'IDLE' || status.status === 'COMPLETED' || status.status === 'ERROR' || status.status === 'STOPPED';
  const isRunning = status?.status === 'RUNNING';
  const isPaused = status?.status === 'PAUSED';
  const progressPercent = status ? status.progress * 100 : 0;
  const progressFill = Math.min(100, Math.max(0, progressPercent));

  const withRunId = (path: string) => (status?.run_id ? `${path}${path.includes('?') ? '&' : '?'}run_id=${encodeURIComponent(status.run_id)}` : path);

  const telemetry = status?.telemetry || undefined;
  const rawProcessed = telemetry?.raw.processed ?? status?.processed_count ?? 0;
  const metaFinalized = telemetry?.rbta.finalized_meta_alerts ?? 0;
  const latestMeta = telemetry?.latest_meta_alert;
  const decisionCounts = telemetry?.decision_counts;
  const selectedManifest = datasetsData?.items.find((item) => item.name === selectedDataset);
  const fullCorpusReady = catalogStatus?.status === 'COMPLETED' && catalogStatus.pending_files === 0 && catalogStatus.failed_files === 0 && catalogStatus.invalid_files === 0;
  const selectedDatasetReady = selectedDataset === '__ALL__'
    ? fullCorpusReady
    : Boolean(selectedManifest && (selectedManifest.inspection_status === 'pending' || selectedManifest.is_valid));
  const liveStage: PipelineStageId = telemetry?.latest_meta_alert ? 'DECISION' : 'RBTA';
  const inspectedStage = activeStage ?? liveStage;

  return (
    <>
      <PageHeader
        breadcrumbs={['Riset', 'Replay sidang']}
        title="Replay sidang RBTA–Isolation Forest"
        description="Putar ulang data penelitian: alert masuk → meta-alert → 7 fitur → skor keanehan → keputusan, lengkap dengan batas klaim dan bukti asli."
      />

      <div className="px-6 py-8 lg:px-10 space-y-8">
        {/* Zona 1: Kontrol */}
        <ZoneSection
          zoneId="replay-zone-kontrol"
          index="Zona 1"
          title="Kontrol"
          description="Dataset, kecepatan, tombol aksi, dan progres replay."
        >
          <DatasetCatalogPanel
            status={catalogStatus}
            disabled={!isIdle || isLoading}
            onRefresh={() => handleAction(refreshDatasetCatalog)}
          />
          <div className="p-6 rounded-xl border border-kumo-hairline bg-kumo-canvas shadow-xs space-y-5">
            <div className="flex flex-wrap items-center justify-between gap-5">
              <div className="flex flex-wrap items-center gap-5">
                <div>
                  <label htmlFor="demo-dataset" className="block text-[11px] font-semibold mb-1.5 text-kumo-subtle uppercase tracking-wider">
                    Dataset untuk replay
                  </label>
                  <div className="w-full min-w-0 sm:w-70">
                    <select
                      id="demo-dataset"
                      value={selectedDataset}
                      onChange={(e) => setSelectedDataset(e.target.value)}
                      disabled={!isIdle || isLoading || !datasetsData?.items?.length}
                      className="w-full px-3.5 py-2 border border-kumo-hairline rounded-lg text-sm bg-kumo-recessed/40 text-kumo-strong focus-visible:ring-2 focus-visible:ring-kumo-brand cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      <option value="__ALL__">Semua dataset (berurutan)</option>
                      {datasetsData?.items?.map((ds) => (
                        <option key={ds.name} value={ds.name}>
                          {ds.name} · {ds.classification} · {ds.inspection_status === 'pending' ? 'menunggu indeks' : `${ds.total_events.toLocaleString('id-ID')} alert`}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>

                <div>
                  <label htmlFor="demo-speed" className="block text-[11px] font-semibold mb-1.5 text-kumo-subtle uppercase tracking-wider">
                    Kecepatan replay
                  </label>
                  <div className="w-full min-w-0 sm:w-56">
                    <select
                      id="demo-speed"
                      value={speed}
                      onChange={(e) => setSpeed(e.target.value as any)}
                      disabled={!isIdle || isLoading}
                      className="w-full px-3.5 py-2 border border-kumo-hairline rounded-lg text-sm bg-kumo-recessed/40 text-kumo-strong focus-visible:ring-2 focus-visible:ring-kumo-brand cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      <option value="1">1× (mengikuti waktu event)</option>
                      <option value="10">10×</option>
                      <option value="100">100×</option>
                      <option value="MAX">Cepat sekali (untuk uji kecepatan)</option>
                    </select>
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-3 mt-2 sm:mt-0">
                {isIdle && (
                  <Button
                    variant="primary"
                    size="sm"
                    onClick={() => handleAction(() => startReplay(selectedDataset, speed))}
                    disabled={isLoading || !selectedDataset || !selectedDatasetReady}
                  >
                    <Play size={14} weight="fill" className="mr-1" /> Mulai replay
                  </Button>
                )}

                {isRunning && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleAction(pauseReplay)}
                    disabled={isLoading}
                  >
                    <Pause size={14} weight="fill" className="mr-1" /> Jeda
                  </Button>
                )}

                {isPaused && (
                  <Button
                    variant="primary"
                    size="sm"
                    onClick={() => handleAction(resumeReplay)}
                    disabled={isLoading}
                  >
                    <FastForward size={14} weight="fill" className="mr-1" /> Lanjut
                  </Button>
                )}

                {(isRunning || isPaused) && (
                  <Button
                    variant="destructive"
                    size="sm"
                    onClick={() => handleAction(stopReplay)}
                    disabled={isLoading}
                  >
                    <Stop size={14} weight="fill" className="mr-1" /> Hentikan
                  </Button>
                )}

                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setShowResetConfirm(true)}
                  disabled={isLoading || status?.status === 'IDLE'}
                >
                  <ArrowClockwise size={14} className="mr-1" /> Siapkan sesi baru
                </Button>
              </div>
            </div>

            {status && (
              <div className="pt-4 border-t border-kumo-hairline">
                <div className="flex justify-between text-xs mb-2 font-mono">
                  <span className="text-kumo-subtle">Progres replay {status.total_count <= 0 ? '(menunggu total)' : ''}</span>
                  <span className="font-semibold text-kumo-strong">{status.total_count > 0 ? `${progressPercent.toFixed(1)}% (${formatNumber(status.processed_count)} / ${formatNumber(status.total_count)})` : `${formatNumber(status.processed_count)} diproses`}</span>
                </div>
                <div className="w-full h-2.5 rounded-full overflow-hidden bg-kumo-recessed">
                  <div
                    className="h-full bg-kumo-brand transition-all duration-300 rounded-full"
                    style={{ width: status.total_count > 0 ? `${progressFill}%` : '100%' }}
                    role="progressbar"
                    aria-label="Progres replay"
                    aria-valuemin={0}
                    aria-valuemax={100}
                    aria-valuenow={Math.round(progressFill)}
                  />
                </div>
              </div>
            )}
          </div>

          {status?.status === 'ERROR' && status.last_error && (
            <Banner
              variant="error"
              size="sm"
              title="Replay gagal dijalankan"
              description={`Data berhenti di baris ${String(status.last_error.line_number)} pada ${String(status.last_error.dataset)}. Pilih data lain yang valid atau siapkan sesi baru. Detail: ${String(status.last_error.error_message)}`}
            />
          )}
        </ZoneSection>

        {/* Zona 2: Alur */}
        <ZoneSection
          zoneId="replay-zone-alur"
          index="Zona 2"
          title="Alur"
          description="Alur pemrosesan, meta-alert terkini, dan jejak pemrosesan."
        >
          <ReplayPipelineVisualizer
            status={status}
            telemetry={telemetry}
            activeStage={activeStage}
            onSelectStage={setActiveStage}
          />

          <CurrentMetaAlertCard
            latestMeta={latestMeta}
            rawProcessed={rawProcessed}
            metaFinalized={metaFinalized}
            decisionCounts={decisionCounts}
          />

          <PipelineStageDetail
            activeStage={inspectedStage}
            telemetry={telemetry}
            status={status}
          />

          <ProcessingTrace trace={telemetry?.trace} />
        </ZoneSection>

        {/* Zona 3: Bukti */}
        <ZoneSection
          zoneId="replay-zone-bukti"
          index="Zona 3"
          title="Bukti"
          description="Evaluasi, pesan Telegram yang belum dikirim, dan ringkasan bukti sesi replay."
        >
          {status?.status === 'COMPLETED' && (
            <Banner
              variant="default"
              size="base"
              title="Replay selesai dan bukti asli tersimpan"
              description={`${formatNumber(status.total_count)} alert diproses dalam ${formatDuration(status.wall_clock_elapsed_seconds)} (${status.events_per_second.toFixed(1)} alert/detik). Lanjutkan ke evaluasi lengkap atau telusuri meta-alert.`}
            >
              <Banner.Action onClick={() => navigate(withRunId('/meta-alerts'))}>
                Telusuri meta-alert <ArrowRight size={14} className="ml-1" />
              </Banner.Action>
            </Banner>
          )}

          <LiveEvaluationPanel live={telemetry?.evaluation_live} eventsPerSecond={status?.events_per_second ?? 0} />

          <PostReplayEvaluation
            replayStatus={status?.status}
            evaluation={evaluation}
            onStart={() => void handleAction(startEvaluation)}
            onCancel={() => void handleAction(cancelEvaluation)}
            onDownload={() => void downloadEvaluationArtifact()}
          />

          <DeferredTelegramOutbox />

          <div className="p-6 rounded-xl border border-kumo-hairline bg-kumo-canvas shadow-xs space-y-5">
            <h3 className="font-semibold text-xs uppercase tracking-wider text-kumo-strong pb-3 border-b border-kumo-hairline">
              Ringkasan bukti sesi replay
            </h3>
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-5">
              <MetricCard label="Status replay" value={status?.status || 'IDLE'} sub="Status replay" />
              <MetricCard label="Alert diproses" value={status ? formatNumber(status.processed_count) : '0'} sub="Alert valid dari dataset" />
              <MetricCard label="Total dataset" value={status ? formatNumber(status.total_count) : '0'} sub="Jumlah alert menurut manifest dataset" />
              <MetricCard label={TERMS.throughput} value={status ? formatNumber(status.events_per_second) : '0'} sub="Kecepatan pada host replay" />
            </div>
            {status && status.run_id && (
              <div className="text-xs font-mono space-y-3 pt-2 border-t border-kumo-hairline">
                <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                  <span className="text-kumo-subtle">ID sesi replay:</span>
                  <span className="font-semibold text-kumo-strong">{status.run_id}</span>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                  <span className="text-kumo-subtle">Sumber dataset:</span>
                  <span className="text-kumo-default">{status.dataset}</span>
                </div>
                {status.dataset_mode === 'all' && (
                  <>
                    <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                      <span className="text-kumo-subtle">Berkas saat ini:</span>
                      <span className="text-kumo-default">{status.current_dataset || '-'}</span>
                    </div>
                    <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                      <span className="text-kumo-subtle">Urutan dataset:</span>
                      <span className="text-kumo-default">
                        {status.current_dataset_index !== undefined && status.dataset_count !== undefined
                          ? `${(status.current_dataset_index || 0) + 1} / ${status.dataset_count}`
                          : '-'}
                      </span>
                    </div>
                  </>
                )}
                <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                  <span className="text-kumo-subtle">Waktu kejadian saat ini:</span>
                  <span className="text-kumo-default">{status.current_event_time || '-'}</span>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40">
                  <span className="text-kumo-subtle">Lama berjalan:</span>
                  <span className="text-kumo-default">{formatDuration(status.wall_clock_elapsed_seconds)}</span>
                </div>
                <div className="flex justify-between items-center py-1.5">
                  <span className="text-kumo-subtle">Model Isolation Forest:</span>
                  <span className="text-kumo-default">{status.model_version}</span>
                </div>
              </div>
            )}
          </div>
        </ZoneSection>
      </div>

      <DialogRoot open={showResetConfirm} onOpenChange={(o) => { if (!o) setShowResetConfirm(false); }}>
        <Dialog className="max-w-md w-full p-6 bg-kumo-canvas border border-kumo-hairline shadow-2xl rounded-xl">
          <DialogTitle className="text-base font-bold text-kumo-strong">Siapkan run replay baru?</DialogTitle>
          <DialogDescription className="text-xs text-kumo-subtle mt-2 leading-relaxed">
            Sistem akan membuat sesi terpisah. Data dan bukti asli dari sesi {status?.run_id?.slice(0, 8)} tetap disimpan untuk audit.
          </DialogDescription>
          <div className="flex justify-end gap-3 pt-4 mt-4 border-t border-kumo-hairline">
            <DialogClose>
              <Button variant="ghost" size="sm" onClick={() => setShowResetConfirm(false)}>
                Batal
              </Button>
            </DialogClose>
            <Button
              variant="primary"
              size="sm"
              onClick={handleConfirmReset}
            >
              Konfirmasi
            </Button>
          </div>
        </Dialog>
      </DialogRoot>
    </>
  );
}
