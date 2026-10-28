import { apiFetch } from './client';
import { MetaAlertListSchema, MetaAlertSchema, TraceSchema } from './schemas';
import type { MetaAlertList, MetaAlert, Trace } from './schemas';

export interface MetaAlertsQueryParams {
  page?: number;
  page_size?: number;
  decision?: string;
  action?: string;
  agent_id?: string;
  rule_group_primary?: string;
  start?: string;
  end?: string;
  search?: string;
  sort_by?: string;
  sort_order?: 'asc' | 'desc';
  run_id?: string;
}

export async function fetchMetaAlerts(params: MetaAlertsQueryParams = {}): Promise<MetaAlertList> {
  const queryParams = new URLSearchParams();
  if (params.page) queryParams.set('page', String(params.page));
  if (params.page_size) queryParams.set('page_size', String(params.page_size));
  if (params.decision) queryParams.set('decision', params.decision);
  if (params.action) queryParams.set('action', params.action);
  if (params.agent_id) queryParams.set('agent_id', params.agent_id);
  if (params.rule_group_primary) queryParams.set('rule_group_primary', params.rule_group_primary);
  if (params.start) queryParams.set('start', params.start);
  if (params.end) queryParams.set('end', params.end);
  if (params.search) queryParams.set('search', params.search);
  if (params.sort_by) queryParams.set('sort_by', params.sort_by);
  if (params.sort_order) queryParams.set('sort_order', params.sort_order);
  if (params.run_id) queryParams.set('run_id', params.run_id);

  const qs = queryParams.toString();
  const url = `/meta-alerts${qs ? `?${qs}` : ''}`;
  const data = await apiFetch<unknown>(url);
  return MetaAlertListSchema.parse(data);
}

export async function fetchMetaAlert(id: number, runId?: string): Promise<MetaAlert> {
  const query = runId ? `?run_id=${encodeURIComponent(runId)}` : '';
  const data = await apiFetch<unknown>(`/meta-alerts/${id}${query}`);
  return MetaAlertSchema.parse(data);
}

export async function fetchMetaAlertTrace(id: number, runId?: string): Promise<Trace> {
  const query = runId ? `?run_id=${encodeURIComponent(runId)}` : '';
  const data = await apiFetch<unknown>(`/meta-alerts/${id}/trace${query}`);
  return TraceSchema.parse(data);
}
