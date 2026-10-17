import { usePollingQuery } from '@/hooks/usePolling';
import { fetchLiveStatus, type LiveStatus } from '@/api/live';
import { Pulse } from '@phosphor-icons/react';

/** Siklus dianggap basi bila tidak ada siklus sukses selama ambang ini. */
export const LIVE_STALE_AFTER_MS = 120_000;

interface LiveStatusPanelProps {
  isLoading: boolean;
  isError: boolean;
  data: LiveStatus | null;
  errorMessage?: string;
  onRetry: () => void;
}

function formatLag(sec: number | null): string {
  if (sec === null || Number.isNaN(sec)) return '-';
  if (sec < 60) return `${sec.toFixed(1)} dtk`;
  return `${(sec / 60).toFixed(1)} mnt`;
}

export function LiveStatusPanel({ isLoading, isError, data, errorMessage, onRetry }: LiveStatusPanelProps) {
  if (isLoading) {
    return (
      <div className="p-6 rounded-xl border border-kumo-hairline bg-kumo-canvas shadow-xs">
        <p role="status" className="text-xs text-kumo-subtle">Memuat status live…</p>
      </div>
    );
  }

  if (isError || !data) {
    return (
      <div className="p-6 rounded-xl border border-kumo-hairline bg-kumo-canvas shadow-xs space-y-3">
        <p role="alert" className="text-xs text-red-600">
          Gagal memuat status live{errorMessage ? `: ${errorMessage}` : ''}
        </p>
        <button
          type="button"
          onClick={onRetry}
          className="px-4 py-2 rounded-lg text-sm font-semibold border border-kumo-hairline"
        >
          Coba lagi
        </button>
      </div>
    );
  }

  const excludedTotal = data.excluded_alerts_total ?? {};
  const excludedSum = Object.values(excludedTotal).reduce((sum, n) => sum + n, 0);
  const stale = data.last_cycle_at
    ? Date.now() - new Date(data.last_cycle_at).getTime() > LIVE_STALE_AFTER_MS
    : data.worker_alive;

  return (
    <div className="p-6 rounded-xl border border-kumo-hairline bg-kumo-canvas shadow-xs space-y-4">
      <div className="flex items-center gap-3 pb-3 border-b border-kumo-hairline">
        <div className="w-8 h-8 rounded-lg border border-kumo-hairline bg-kumo-recessed text-kumo-strong flex items-center justify-center">
          <Pulse size={18} />
        </div>
        <h3 className="font-semibold text-xs uppercase tracking-wider text-kumo-strong">
          Status Live Stream
        </h3>
        <span
          className={`ml-auto font-mono text-xs font-bold ${data.worker_alive ? 'text-emerald-500' : 'text-kumo-subtle'}`}
        >
          {data.worker_alive ? 'Worker hidup' : 'Worker berhenti'}
        </span>
      </div>

      {stale && data.worker_alive && (
        <p role="status" className="text-xs text-amber-600">
          Data basi, siklus terakhir lebih dari 2 menit lalu. Periksa koneksi Indexer/API dan log backend.
        </p>
      )}
      {!data.worker_alive && (
        <p className="text-xs text-kumo-subtle">
          Worker berhenti. Backend berjalan dalam mode replay/demo. Aktifkan via RBTA_LIVE_WORKER_ENABLED=true.
        </p>
      )}

      <dl className="grid grid-cols-2 lg:grid-cols-4 gap-5 text-xs">
        <div>
          <dt className="text-kumo-subtle font-medium">Alert unik diproses</dt>
          <dd className="font-mono font-semibold text-kumo-strong text-base">
            {data.ingested_total ?? '-'}
          </dd>
        </div>
        <div>
          <dt className="text-kumo-subtle font-medium">Gagal beruntun</dt>
          <dd className={`font-mono font-semibold text-base ${data.consecutive_failures > 0 ? 'text-red-600' : 'text-kumo-strong'}`}>
            {data.consecutive_failures}
          </dd>
        </div>
        <div>
          <dt className="text-kumo-subtle font-medium">Model terpin</dt>
          <dd className="font-mono font-semibold text-kumo-strong">{data.live_model_version ?? '-'}</dd>
        </div>
        <div>
          <dt className="text-kumo-subtle font-medium">Karantina</dt>
          <dd className="font-mono font-semibold text-kumo-strong">{data.quarantine_total ?? '-'}</dd>
        </div>
        <div>
          <dt className="text-kumo-subtle font-medium">Lag siklus</dt>
          <dd className="font-mono text-kumo-default">{formatLag(data.lag_sec)}</dd>
        </div>
        <div>
          <dt className="text-kumo-subtle font-medium">Lag event</dt>
          <dd className="font-mono text-kumo-default">{formatLag(data.event_lag_sec)}</dd>
        </div>
        <div>
          <dt className="text-kumo-subtle font-medium">Antrean Telegram</dt>
          <dd className="font-mono text-kumo-default">{data.outbox_pending}</dd>
        </div>
        <div>
          <dt className="text-kumo-subtle font-medium">Buffer</dt>
          <dd className="font-mono text-kumo-default">
            {data.buffer_size === null ? 'nonaktif' : data.buffer_size}
          </dd>
        </div>
      </dl>

      {(data.excluded_agents?.length ?? 0) > 0 && (
        <div className="text-xs text-kumo-subtle space-y-1">
          <p>
            Agen uji dikecualikan dari ingestion ({data.excluded_agents?.join(', ')}):{' '}
            <span className="font-mono font-semibold text-kumo-strong">{excludedSum}</span> alert unik tidak diproses.
          </p>
          {excludedSum > 0 && (
            <p className="font-mono">
              {Object.entries(excludedTotal)
                .map(([agent, count]) => `${agent}: ${count}`)
                .join(' · ')}
            </p>
          )}
        </div>
      )}

      {data.last_error && (
        <p role="alert" className="text-xs text-red-600 font-mono break-words">
          Error terakhir: {data.last_error}
        </p>
      )}
      {data.tls_verify === false && (
        <p className="text-xs text-amber-600">
          Verifikasi TLS Indexer/API nonaktif. Rentan MITM; aktifkan untuk produksi.
        </p>
      )}
    </div>
  );
}

export function LiveStatusCard() {
  const { data, isLoading, isError, error, refetch } = usePollingQuery(
    ['live-status'],
    fetchLiveStatus,
    5000,
  );
  return (
    <LiveStatusPanel
      isLoading={isLoading}
      isError={isError}
      data={data ?? null}
      errorMessage={error instanceof Error ? error.message : undefined}
      onRetry={() => void refetch()}
    />
  );
}
