import { z } from 'zod';
import { apiFetch } from './client';

export const LiveStatusSchema = z.object({
  worker_alive: z.boolean(),
  cycles_completed: z.number().int().nonnegative(),
  consecutive_failures: z.number().int().nonnegative(),
  last_error: z.string().nullable(),
  last_cycle_at: z.string().nullable(),
  live_model_version: z.string().nullable(),
  recent_poll_cursor: z.string().nullable(),
  lag_sec: z.number().nullable(),
  buffer_size: z.number().int().nonnegative().nullable(),
  buffer_stats: z.record(z.string(), z.number().int().nonnegative().nullable()).nullable(),
  outbox_pending: z.number().int().nonnegative(),
  ingested_total: z.number().int().nonnegative().nullable(),
  dispatcher: z.unknown().nullable(),
  quarantine_total: z.number().int().nonnegative().nullable(),
  newest_scored_event_time: z.string().nullable(),
  newest_ingested_event_time: z.string().nullable(),
  event_lag_sec: z.number().nullable(),
  tls_verify: z.boolean().nullable(),
  // Opsional: backend lama tidak mengirim field ini.
  excluded_agents: z.array(z.string()).optional(),
  excluded_alerts_total: z.record(z.string(), z.number().int().nonnegative()).optional(),
  disk: z
    .record(z.string(), z.object({ used_pct: z.number(), warning: z.boolean() }).passthrough().nullable())
    .optional(),
});

export type LiveStatus = z.infer<typeof LiveStatusSchema>;

export async function fetchLiveStatus(): Promise<LiveStatus> {
  const data = await apiFetch<unknown>('/live/status');
  return LiveStatusSchema.parse(data);
}
