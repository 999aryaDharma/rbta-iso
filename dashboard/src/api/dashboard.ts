import { apiFetch } from './client';
import {
  DashboardSummarySchema,
  AgentStateSchema,
  BucketStateSchema,
  RawAlertListSchema,
  TimeseriesSchema,
  SystemInfoSchema,
  IntegrationsSchema,
} from './schemas';
import type {
  DashboardSummary,
  AgentState,
  BucketState,
  RawAlertList,
  TimeseriesData,
  SystemInfo,
  IntegrationsData,
} from './schemas';
import { z } from 'zod';

export async function fetchSummary(runId?: string): Promise<DashboardSummary> {
  const query = runId ? `?run_id=${encodeURIComponent(runId)}` : '';
  const data = await apiFetch<unknown>(`/dashboard/summary${query}`);
  return DashboardSummarySchema.parse(data);
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
  range?: { start: string; end: string },
): Promise<TimeseriesData> {
  const queryParams = new URLSearchParams();
  queryParams.set('window_hours', String(windowHours));
  if (range) {
    queryParams.set('start', range.start);
    queryParams.set('end', range.end);
  }
  if (runId) queryParams.set('run_id', runId);
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
