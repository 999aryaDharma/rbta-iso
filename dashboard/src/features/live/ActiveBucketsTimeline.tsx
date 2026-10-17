import { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { usePollingQuery } from '@/hooks/usePolling';
import { fetchBuckets } from '@/api/dashboard';
import { buildTimelineBars, type TimelineBar } from './bucketTimeline';
import { formatNumber, formatSeconds } from '@/lib/formatters';
import { Table } from '@cloudflare/kumo/components/table';
import { Badge } from '@cloudflare/kumo/components/badge';
import { TERMS } from '@/lib/labels';

interface ActiveBucketsTimelineProps {
  bars: TimelineBar[];
  windowMinutes: number;
  onSelect: (metaId: number) => void;
  onOpenBucket?: (bar: TimelineBar) => void;
}

function windowSeconds(startIso: string, endIso: string): number | null {
  const s = new Date(startIso).getTime();
  const e = new Date(endIso).getTime();
  if (Number.isNaN(s) || Number.isNaN(e) || e < s) return null;
  return (e - s) / 1000;
}

export function ActiveBucketsTimeline({ bars, windowMinutes, onSelect, onOpenBucket }: ActiveBucketsTimelineProps) {
  if (bars.length === 0) {
    return (
      <div className="p-6 rounded-xl border border-kumo-hairline bg-kumo-canvas shadow-xs">
        <p role="status" className="text-xs text-kumo-subtle">
          Belum ada kelompok alert yang terbuka dalam {windowMinutes} menit terakhir. Pemrosesan berhenti atau belum ada alert masuk.
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-kumo-hairline bg-kumo-canvas shadow-xs overflow-hidden">
      <div className="px-6 py-4 border-b border-kumo-hairline">
        <h3 className="font-semibold text-xs uppercase tracking-wider text-kumo-strong">
          {TERMS.bucketOpen}: {windowMinutes} menit terakhir
        </h3>
        <p className="text-xs text-kumo-subtle mt-1">
          Tiap baris adalah kelompok alert yang masih bertambah. Bukan bukti serangan; tautan ke meta-alert baru muncul setelah kelompok ditutup.
        </p>
      </div>
      <Table>
        <Table.Header>
          <Table.Row className="bg-kumo-recessed/50 text-[11px] uppercase tracking-wider">
            <Table.Head>Kelompok</Table.Head>
            <Table.Head className="text-right">Alert</Table.Head>
            <Table.Head className="text-right">Lama pengelompokan</Table.Head>
            <Table.Head className="text-right">Keparahan maks.</Table.Head>
            <Table.Head className="text-center">Status</Table.Head>
          </Table.Row>
        </Table.Header>
        <Table.Body>
          {bars.map((b) => (
            <Table.Row key={b.key} className="hover:bg-kumo-recessed/40 transition-colors text-xs">
              <Table.Cell>
                <button
                  type="button"
                  aria-label={`Buka isi kelompok ${b.agent_id} ${b.rule_group_primary}`}
                  onClick={() => onOpenBucket?.(b)}
                  className="text-left rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-kumo-brand hover:opacity-80"
                >
                  <span className="font-mono font-semibold text-kumo-brand underline underline-offset-2">
                    {b.agent_id} · {b.rule_group_primary}
                  </span>
                  {b.agent_name && (
                    <span className="block font-mono text-[11px] text-kumo-subtle">{b.agent_name}</span>
                  )}
                </button>
              </Table.Cell>
              <Table.Cell className="text-right font-mono font-bold text-kumo-strong">
                {formatNumber(b.alert_count)}
              </Table.Cell>
              <Table.Cell className="text-right font-mono text-kumo-subtle">
                {formatSeconds(windowSeconds(b.start_time, b.end_time))}
              </Table.Cell>
              <Table.Cell className="text-right font-mono text-kumo-default">
                {b.max_severity} / 15 ({b.tier})
              </Table.Cell>
              <Table.Cell className="text-center">
                {b.finalized && b.meta_id != null ? (
                  <button
                    type="button"
                    aria-label={`${b.agent_id} ${b.rule_group_primary}, menjadi meta-alert ${b.meta_id}`}
                    onClick={() => onSelect(b.meta_id as number)}
                    className="font-mono font-semibold text-kumo-brand underline underline-offset-2 hover:opacity-80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-kumo-brand rounded"
                  >
                    Meta-alert #{b.meta_id}
                  </button>
                ) : (
                  <span className="inline-flex flex-col items-center gap-1">
                    <Badge variant="secondary">Masih bertambah</Badge>
                    {b.meta_id != null && (
                      <span className="font-mono text-[11px] text-kumo-subtle">akan menjadi meta-alert #{b.meta_id}</span>
                    )}
                  </span>
                )}
              </Table.Cell>
            </Table.Row>
          ))}
        </Table.Body>
      </Table>
    </div>
  );
}

export function ActiveBucketsTimelineCard({ windowMinutes = 15 }: { windowMinutes?: number }) {
  const navigate = useNavigate();
  const { data: buckets = [] } = usePollingQuery(['buckets', 'live'], () => fetchBuckets(), 5000);
  const now = Date.now();
  const bars = useMemo(
    () => buildTimelineBars(buckets, now, windowMinutes * 60_000),
    [buckets, now, windowMinutes],
  );
  return (
    <ActiveBucketsTimeline
      bars={bars}
      windowMinutes={windowMinutes}
      onSelect={(metaId) => navigate(`/meta-alerts/${metaId}`)}
      onOpenBucket={(b) =>
        navigate(`/live/buckets/${encodeURIComponent(b.agent_id)}/${encodeURIComponent(b.rule_group_primary)}`)
      }
    />
  );
}
