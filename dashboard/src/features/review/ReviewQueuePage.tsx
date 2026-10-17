import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { fetchReviewQueue, VERDICT_LABELS } from '@/api/review';
import { PageHeader } from '@/components/shared/PageHeader';
import { DecisionBadge } from '@/components/shared/DecisionBadge';
import { formatScore } from '@/lib/formatters';

const REASON_LABELS: Record<string, string> = {
  ESCALATE: 'Semua ESCALATE',
  SAMPLE_SUPPRESS: 'Sampel SUPPRESS',
  SAMPLE_DIGEST: 'Sampel DAILY_DIGEST',
};

export function ReviewQueuePage() {
  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['review-queue', 7],
    queryFn: () => fetchReviewQueue(7),
  });

  const labeled = data?.items.filter((i) => i.verdict).length ?? 0;

  return (
    <>
      <PageHeader
        breadcrumbs={['Operasi', 'Review Queue']}
        title="Review Queue"
        description="Semua ESCALATE + sampel acak deterministik 5% SUPPRESS dan 5% DAILY_DIGEST per hari (seed = tanggal), 7 hari terakhir"
      />
      <div className="px-6 py-8 lg:px-10 space-y-4">
        {isLoading && <p role="status" className="text-xs text-kumo-subtle">Memuat antrean review…</p>}
        {isError && (
          <div className="space-y-2">
            <p role="alert" className="text-xs text-red-600">
              Gagal memuat antrean{error instanceof Error ? `: ${error.message}` : ''}
            </p>
            <button type="button" onClick={() => void refetch()} className="px-4 py-2 rounded-lg text-sm border border-kumo-hairline">
              Coba lagi
            </button>
          </div>
        )}
        {data && data.items.length === 0 && (
          <p role="status" className="text-xs text-kumo-subtle">Belum ada MetaAlert live untuk direview pada rentang ini.</p>
        )}
        {data && data.items.length > 0 && (
          <>
            <p className="text-xs text-kumo-subtle">
              {labeled} dari {data.items.length} item sudah dilabel. Verdict adalah label analyst pada sampel, bukan ground truth.
            </p>
            <div className="overflow-x-auto rounded-xl border border-kumo-hairline">
              <table className="w-full text-xs">
                <thead className="bg-kumo-recessed text-kumo-subtle text-left">
                  <tr>
                    <th className="p-2">Tanggal</th>
                    <th className="p-2">MetaAlert</th>
                    <th className="p-2">Agent · Group</th>
                    <th className="p-2">Level / Action</th>
                    <th className="p-2">Skor</th>
                    <th className="p-2">Alasan antre</th>
                    <th className="p-2">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((item) => (
                    <tr key={item.meta_id} className="border-t border-kumo-hairline">
                      <td className="p-2 font-mono">{item.date}</td>
                      <td className="p-2 font-mono">
                        <Link to={`/meta-alerts/${item.meta_id}`} className="underline">#{item.meta_id}</Link>
                      </td>
                      <td className="p-2">{item.agent_name ?? item.agent_id} · {item.rule_group_primary}</td>
                      <td className="p-2"><DecisionBadge decision={item.decision ?? ''} action={item.action ?? ''} /></td>
                      <td className="p-2 font-mono">{item.anomaly_score === null ? '-' : formatScore(item.anomaly_score)}</td>
                      <td className="p-2">{REASON_LABELS[item.queue_reason]}</td>
                      <td className="p-2">
                        {item.verdict ? (
                          <span className="font-semibold text-kumo-strong">{VERDICT_LABELS[item.verdict.verdict]}</span>
                        ) : (
                          <span className="text-amber-600">Belum dilabel</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </>
  );
}
