import { z } from 'zod';
import { apiFetch } from './client';

export const VERDICTS = ['incident', 'actionable_benign', 'noise'] as const;
export type Verdict = (typeof VERDICTS)[number];

export const VERDICT_LABELS: Record<Verdict, string> = {
  incident: 'Insiden',
  actionable_benign: 'Benign, perlu tindakan',
  noise: 'Noise',
};

export const AnalystVerdictSchema = z.object({
  meta_id: z.number(),
  verdict: z.enum(VERDICTS),
  note: z.string(),
  labeled_by: z.string(),
  labeled_at: z.string(),
});
export type AnalystVerdict = z.infer<typeof AnalystVerdictSchema>;

export const ReviewQueueItemSchema = z.object({
  date: z.string(),
  meta_id: z.number(),
  agent_id: z.string().nullable(),
  agent_name: z.string().nullable(),
  rule_group_primary: z.string().nullable(),
  decision: z.string().nullable(),
  action: z.string().nullable(),
  anomaly_score: z.number().nullable(),
  alert_count: z.number().nullable(),
  end_time: z.string().nullable(),
  queue_reason: z.enum(['ESCALATE', 'SAMPLE_SUPPRESS', 'SAMPLE_DIGEST']),
  verdict: AnalystVerdictSchema.nullable(),
});
export type ReviewQueueItem = z.infer<typeof ReviewQueueItemSchema>;

export const ReviewQueueSchema = z.object({
  items: z.array(ReviewQueueItemSchema),
  summary: z.array(z.record(z.string(), z.union([z.string(), z.number(), z.null()]))),
  sample_rate: z.number(),
  days: z.array(z.string()),
});
export type ReviewQueue = z.infer<typeof ReviewQueueSchema>;

export async function fetchReviewQueue(days = 7): Promise<ReviewQueue> {
  const data = await apiFetch<unknown>(`/meta-alerts/review-queue?days=${days}`);
  return ReviewQueueSchema.parse(data);
}

export async function postMetaAlertVerdict(
  metaId: number,
  body: { verdict: Verdict; note?: string; labeled_by?: string },
): Promise<AnalystVerdict> {
  const data = await apiFetch<unknown>(`/meta-alerts/${metaId}/verdict`, {
    method: 'POST',
    body: JSON.stringify(body),
  });
  return AnalystVerdictSchema.parse(data);
}
