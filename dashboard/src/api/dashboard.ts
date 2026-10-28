import { apiFetch } from './client';
import {
  DashboardSummarySchema,
  FilterOptionsSchema,
  AgentStateSchema,
  BucketStateSchema,
  RawAlertListSchema,
  TimeseriesSchema,
  SystemInfoSchema,
  IntegrationsSchema,
} from './schemas';
import type {
  DashboardSummary,
  FilterOptions,
  AgentState,
  BucketState,
  RawAlertList,
  TimeseriesData,
  SystemInfo,
  IntegrationsData,
} from './schemas';
import { z } from 'zod';

/** Filter lingkup Overview; semua opsional, dikirim apa adanya ke backend. */
export interface OverviewScope {
  agent_id?: string;
  rule_group_primary?: string;
  start?: string;
  end?: string;
}

function scopeQuery(runId: string | undefined, scope: OverviewScope = {}): URLSearchParams {
  const q = new URLSearchParams();
  if (runId) q.set('run_id', runId);
  for (const [k, v] of Object.entries(scope)) if (v) q.set(k, v);
  return q;
}

export async function fetchSummary(runId?: string, scope?: OverviewScope): Promise<DashboardSummary> {
  const qs = scopeQuery(runId, scope).toString();
  const data = await apiFetch<unknown>(`/dashboard/summary${qs ? `?${qs}` : ''}`);
  return DashboardSummarySchema.parse(data);
}

export async function fetchFilterOptions(runId?: string): Promise<FilterOptions> {
  const qs = scopeQuery(runId).toString();
  const data = await apiFetch<unknown>(`/dashboard/filters${qs ? `?${qs}` : ''}`);
  return FilterOptionsSchema.parse(data);
}

export async function fetchAgents(runId?: string): Promise<AgentState[]> {
  const query = runId ? `?run_id=${encodeURIComponent(runId)}` : '';
  const data = await apiFetch<unknown>(`/dashboard/agents${query}`);
  return z.array(AgentStateSchema).parse(data);
}

export async function fetchBuckets(runId?: string): Promise<BucketState[]> {
  const query = runId ? `?run_id=${encodeURIComponent(runId)}` : '';
  const data = await apiFetch<unknown>(`/dashboard/buckets${query}`);
  return z.array(BucketStateSchema).parse(data);
}

export interface BucketRawAlertsParams {
  page?: number;
  page_size?: number;
  run_id?: string;
}

export async function fetchBucketRawAlerts(
  agentId: string,
  ruleGroup: string,
  params: BucketRawAlertsParams = {},
): Promise<RawAlertList> {
  const queryParams = new URLSearchParams();
  queryParams.set('agent_id', agentId);
  queryParams.set('rule_group_primary', ruleGroup);
  if (params.page) queryParams.set('page', String(params.page));
  if (params.page_size) queryParams.set('page_size', String(params.page_size));
  if (params.run_id) queryParams.set('run_id', params.run_id);
  const data = await apiFetch<unknown>(`/dashboard/buckets/raw-alerts?${queryParams.toString()}`);
  return RawAlertListSchema.parse(data);
}

export async function fetchTimeseries(
  windowHours: number = 24,
  runId?: string,
  scope?: OverviewScope,
): Promise<TimeseriesData> {
  const queryParams = scopeQuery(runId, scope);
  queryParams.set('window_hours', String(windowHours));
  const data = await apiFetch<unknown>(`/dashboard/timeseries?${queryParams.toString()}`);
  return TimeseriesSchema.parse(data);
}

export async function fetchSystemInfo(runId?: string): Promise<SystemInfo> {
  const query = runId ? `?run_id=${encodeURIComponent(runId)}` : '';
  const data = await apiFetch<unknown>(`/dashboard/system${query}`);
  return SystemInfoSchema.parse(data);
}

export async function fetchIntegrations(): Promise<IntegrationsData> {
  const data = await apiFetch<unknown>('/dashboard/integrations');
  return IntegrationsSchema.parse(data);
}
