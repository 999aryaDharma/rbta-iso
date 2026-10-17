import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { postMetaAlertVerdict, VERDICTS, VERDICT_LABELS, type AnalystVerdict, type Verdict } from '@/api/review';
import { formatDateTime } from '@/lib/formatters';

interface AnalystVerdictPanelProps {
  metaId: number;
  current: AnalystVerdict | null | undefined;
}

/** Label analyst untuk evaluasi Bab IV. Label tidak mengubah decision/action model. */
export function AnalystVerdictPanel({ metaId, current }: AnalystVerdictPanelProps) {
  const queryClient = useQueryClient();
  const [note, setNote] = useState(current?.note ?? '');
  const mutation = useMutation({
    mutationFn: (verdict: Verdict) => postMetaAlertVerdict(metaId, { verdict, note }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['meta-alert', metaId] });
      void queryClient.invalidateQueries({ queryKey: ['review-queue'] });
    },
  });
  const shown = mutation.data ?? current ?? null;

  return (
    <div className="p-6 rounded-xl border border-kumo-hairline bg-kumo-canvas shadow-xs space-y-4">
      <h3 className="font-semibold text-xs uppercase tracking-wider text-kumo-strong pb-3 border-b border-kumo-hairline">
        Verdict analyst
      </h3>
      <p className="text-xs text-kumo-subtle">
        Label manusia untuk evaluasi; tidak mengubah keputusan model. Anomaly score bukan label serangan.
      </p>
      <p role="status" className="text-xs">
        {shown ? (
          <>
            Status: <span className="font-semibold text-kumo-strong">{VERDICT_LABELS[shown.verdict]}</span>
            <span className="text-kumo-subtle"> · {formatDateTime(shown.labeled_at)}</span>
          </>
        ) : (
          <span className="text-kumo-subtle">Belum dilabel.</span>
        )}
      </p>
      <label className="block text-xs text-kumo-subtle">
        Catatan
        <textarea
          value={note}
          onChange={(e) => setNote(e.target.value)}
          maxLength={2000}
          rows={2}
          className="mt-1 w-full rounded-lg border border-kumo-hairline bg-kumo-recessed p-2 text-xs text-kumo-default"
        />
      </label>
      <div className="flex flex-wrap gap-2">
        {VERDICTS.map((v) => (
          <button
            key={v}
            type="button"
            disabled={mutation.isPending}
            aria-pressed={shown?.verdict === v}
            onClick={() => mutation.mutate(v)}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold border border-kumo-hairline disabled:opacity-50 ${
              shown?.verdict === v ? 'bg-kumo-recessed text-kumo-strong' : 'text-kumo-default'
            }`}
          >
            {VERDICT_LABELS[v]}
          </button>
        ))}
      </div>
      {mutation.isError && (
        <p role="alert" className="text-xs text-red-600">
          Gagal menyimpan verdict{mutation.error instanceof Error ? `: ${mutation.error.message}` : ''}.
        </p>
      )}
    </div>
  );
}
