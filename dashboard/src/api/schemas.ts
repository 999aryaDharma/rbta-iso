import { z } from 'zod';
import { AnalystVerdictSchema } from './review';

export const DashboardSummarySchema = z.object({
  raw_alert_count: z.number(),
  meta_alert_count: z.number(),
  alert_reduction_rate_percent: z.number().nullable().optional(),
  escalate_count: z.number(),
  digest_count: z.number(),
  suppress_count: z.number(),
  anomalies_detected: z.number(),
  critical_meta_count: z.number(),
  active_buckets_count: z.number(),
  source_mode: z.string(),
  system_status: z.string(),
});

export type DashboardSummary = z.infer<typeof DashboardSummarySchema>;

export const AgentStateSchema = z.object({
  agent_id: z.string(),
  agent_name: z.string(),
  event_count: z.number(),
  warmup_required: z.number(),
  warmup_progress: z.number(),
  is_warmed_up: z.boolean(),
  baseline_gap_seconds: z.number().nullable().optional(),
  ema_gap_seconds: z.number().nullable().optional(),
  base_delta_t_seconds: z.number(),
  current_delta_t_seconds: z.number(),
  active_bucket_count: z.number(),
  status: z.string(),
});

export type AgentState = z.infer<typeof AgentStateSchema>;

export const BucketStateSchema = z.object({
  meta_id: z.number().nullable().optional(),
  finalized: z.boolean().nullish(),
  agent_id: z.string(),
  agent_name: z.string().nullable().optional(),
  rule_group_primary: z.string(),
  start_time: z.string(),
  end_time: z.string(),
  alert_count: z.number(),
  max_severity: z.number(),
});

export type BucketState = z.infer<typeof BucketStateSchema>;

export const MetaAlertSchema = z.object({
  meta_id: z.number(),
  agent_id: z.string(),
  agent_name: z.string(),
  rule_group_primary: z.string(),
  start_time: z.string(),
  end_time: z.string(),
  alert_count: z.number(),
  max_severity: z.number(),
  mitre_tactics: z.array(z.string()).default([]),
  seven_features: z.record(z.string(), z.number()),
  raw_model_score: z.number(),
  anomaly_score: z.number(),
  threshold_used: z.number(),
  decision: z.string(),
  action: z.string(),
  escalate: z.boolean(),
  model_version: z.string(),
  feature_schema_version: z.string(),
  score_calibration_version: z.string(),
  source_alert_ids: z.array(z.string()).default([]),
  metadata: z.record(z.string(), z.unknown()).optional(),
  // Hanya di detail live (T8); null = belum dilabel.
  analyst_verdict: AnalystVerdictSchema.nullable().optional(),
});

export type MetaAlert = z.infer<typeof MetaAlertSchema>;

export const MetaAlertListSchema = z.object({
  items: z.array(MetaAlertSchema),
  total: z.number(),
  page: z.number(),
  page_size: z.number(),
});

export type MetaAlertList = z.infer<typeof MetaAlertListSchema>;

export const RawAlertSchema = z.object({
  wazuh_alert_id: z.string(),
  timestamp: z.string(),
  agent_id: z.string(),
  agent_name: z.string(),
  rule_id: z.string(),
  rule_level: z.number(),
  rule_description: z.string().optional().default(''),
  rule_group_primary: z.string(),
  rule_groups_all: z.array(z.string()).default([]),
  mitre_tactics: z.array(z.string()).default([]),
  mitre_techniques: z.array(z.string()).default([]),
  srcip: z.string().nullable().optional(),
  location: z.string().optional().default(''),
  decoder: z.string().optional().default(''),
  full_log: z.string().optional().default(''),
  agent_criticality: z.number(),
  metadata: z.record(z.string(), z.unknown()).optional(),
  original_source_payload: z.record(z.string(), z.unknown()).nullable().optional(),
  source_index: z.string().optional().default(''),
  source_document_id: z.string().optional().default(''),
  source_mode: z.string().optional().default(''),
  ingested_at: z.string().optional().default(''),
});

export type RawAlert = z.infer<typeof RawAlertSchema>;

export const RawAlertListSchema = z.object({
  meta_id: z.number().nullable().optional(),
  source_total: z.number(),
  resolved_total: z.number(),
  filtered_total: z.number(),
  unresolved_alert_ids: z.array(z.string()).default([]),
  items: z.array(RawAlertSchema),
  page: z.number(),
  page_size: z.number(),
});

export type RawAlertList = z.infer<typeof RawAlertListSchema>;

export const PipelineTraceItemSchema = z.object({
  timestamp: z.string(),
  stage: z.string(),
  message: z.string(),
  detail: z.string().optional(),
});

export type PipelineTraceItem = z.infer<typeof PipelineTraceItemSchema>;

export const PipelineLatestMetaAlertSchema = z.object({
  meta_id: z.number(),
  agent_id: z.string(),
  agent_name: z.string(),
  rule_group_primary: z.string(),
  start_time: z.string().nullable().optional(),
  end_time: z.string().nullable().optional(),
  alert_count: z.number(),
  max_severity: z.number(),
  mitre_tactics: z.array(z.string()).optional(),
  seven_features: z.record(z.string(), z.number()).optional(),
  raw_model_score: z.number().optional(),
  anomaly_score: z.number().optional(),
  threshold_used: z.number().optional(),
  margin: z.number().optional(),
  decision: z.string().optional(),
  action: z.string().optional(),
  escalate: z.boolean().optional(),
  model_version: z.string().optional(),
});

export type PipelineLatestMetaAlert = z.infer<typeof PipelineLatestMetaAlertSchema>;

export const LiveEvaluationSchema = z.object({
  schema_version: z.string(),
  raw_alerts: z.number(),
  finalized_meta_alerts: z.number(),
  active_meta_alerts: z.number(),
  triage_units_current: z.number(),
  live_arr_percent: z.number(),
  decision_distribution: z.record(z.string(), z.number()),
  action_distribution: z.record(z.string(), z.number()),
  threshold: z.object({ above_count: z.number(), above_rate_percent: z.number() }),
  score_distribution: z.object({
    count: z.number(),
    min: z.number().nullable(),
    max: z.number().nullable(),
    mean: z.number().nullable(),
    bins: z.array(z.string()),
    histogram: z.array(z.number()),
  }),
  reference_range_exceedance_count: z.number(),
  evidence_coverage_percent: z.number(),
  source_reference_coverage_percent: z.number(),
  model_provenance: z.record(z.string(), z.unknown()),
  claim_boundary: z.object({
    accuracy_available: z.boolean(),
    arr_interpretation: z.string(),
    score_interpretation: z.string(),
    silhouette_interpretation: z.string(),
    contamination_interpretation: z.string(),
  }),
});

export type LiveEvaluation = z.infer<typeof LiveEvaluationSchema>;

export const PipelineTelemetrySchema = z.object({
  raw: z.object({
    processed: z.number(),
    evidence_count: z.number(),
    last_alert: z.record(z.string(), z.unknown()).nullable().optional(),
  }),
  rbta: z.object({
    active_buckets: z.number(),
    finalized_meta_alerts: z.number(),
    active_agents: z.number(),
  }),
  latest_meta_alert: PipelineLatestMetaAlertSchema.nullable().optional(),
  decision_counts: z.record(z.string(), z.number()).optional(),
  output: z.object({
    telegram_deferred_count: z.number(),
    latest_payload: z.record(z.string(), z.unknown()).nullable().optional(),
  }),
  trace: z.array(PipelineTraceItemSchema).optional(),
  evaluation_live: LiveEvaluationSchema.optional(),
});

export type PipelineTelemetry = z.infer<typeof PipelineTelemetrySchema>;

export const TelegramPayloadSchema = z.object({
  timestamp: z.string(),
  run_id: z.string(),
  meta_id: z.number(),
  idempotency_key: z.string(),
  decision: z.string(),
  action: z.string(),
  anomaly_score: z.number(),
  threshold: z.number(),
  model_version: z.string(),
  agent_id: z.string(),
  agent_name: z.string(),
  rule_group_primary: z.string(),
  alert_count: z.number(),
  max_severity: z.number(),
  message: z.string(),
});

export type TelegramPayload = z.infer<typeof TelegramPayloadSchema>;

export const TelegramPayloadListSchema = z.object({
  items: z.array(TelegramPayloadSchema),
  total_count: z.number(),
});

export type TelegramPayloadList = z.infer<typeof TelegramPayloadListSchema>;

export const ReplayStatusSchema = z.object({
  run_id: z.string().nullable(),
  status: z.enum(['IDLE', 'RUNNING', 'PAUSED', 'STOPPED', 'COMPLETED', 'ERROR']),
  dataset: z.string().nullable(),
  processed_count: z.number(),
  total_count: z.number(),
  progress: z.number().min(0).max(1),
  updated_at: z.string().optional(),
  current_event_time: z.string().nullable(),
  wall_clock_elapsed_seconds: z.number(),
  speed: z.union([z.number(), z.string()]),
  events_per_second: z.number(),
  model_version: z.string(),
  dataset_mode: z.string().nullable().optional(),
  dataset_count: z.number().nullable().optional(),
  current_dataset: z.string().nullable().optional(),
  current_dataset_index: z.number().nullable().optional(),
  error: z.string().nullable().optional(),
  last_error: z.record(z.string(), z.unknown()).nullable().optional(),
  telemetry: PipelineTelemetrySchema.nullable().optional(),
});

export type ReplayStatus = z.infer<typeof ReplayStatusSchema>;

export const ReplayDatasetSchema = z.object({
  name: z.string(),
  size_bytes: z.number(),
  total_events: z.number().default(0),
  valid_events: z.number().default(0),
  invalid_events: z.number().default(0),
  is_valid: z.boolean().default(true),
  sha256: z.string().default(''),
  timestamp_start: z.string().nullable().optional(),
  timestamp_end: z.string().nullable().optional(),
  compression: z.string().default('none'),
  classification: z.enum(['unclassified', 'golden', 'research']).default('unclassified'),
  random_seed: z.number().nullable().optional(),
  cache_status: z.string().optional(),
  inspection_status: z.enum(['cached', 'pending']).default('pending'),
});

export type ReplayDataset = z.infer<typeof ReplayDatasetSchema>;

export const ReplayDatasetListSchema = z.object({
  items: z.array(ReplayDatasetSchema),
});

export type ReplayDatasetList = z.infer<typeof ReplayDatasetListSchema>;

export const DatasetCatalogStatusSchema = z.object({
  status: z.enum(['IDLE', 'STARTING', 'RUNNING', 'COMPLETED', 'ERROR']),
  total_files: z.number(),
  completed_files: z.number(),
  failed_files: z.number(),
  invalid_files: z.number(),
  pending_files: z.number(),
  current_file: z.string().nullable(),
  last_error: z.record(z.string(), z.unknown()).nullable(),
  errors: z.array(z.record(z.string(), z.unknown())),
  started_at_utc: z.string().nullable(),
  completed_at_utc: z.string().nullable(),
});

export type DatasetCatalogStatus = z.infer<typeof DatasetCatalogStatusSchema>;

export const EvaluationAblationRowSchema = z.object({
  variant: z.string(),
  n_raw: z.number(),
  n_meta: z.number(),
  arr: z.number(),
  context_purity_percent: z.number(),
  context_contamination_percent: z.number(),
});

export const EvaluationStatusSchema = z.object({
  run_id: z.string().nullable(),
  status: z.enum(['IDLE', 'RUNNING', 'COMPLETED', 'ERROR', 'CANCELLED', 'UNAVAILABLE']),
  current_phase: z.string().nullable(),
  completed_phases: z.number(),
  total_phases: z.number(),
  progress_percent: z.number(),
  artifact_available: z.boolean(),
  last_error: z.record(z.string(), z.unknown()).nullable(),
  results: z.object({
    sensitivity: z.array(z.record(z.string(), z.unknown())).optional(),
    recommended_elbow_delta_t_minutes: z.number().nullable().optional(),
    aggregation_ablation: z.array(EvaluationAblationRowSchema).optional(),
    noise_robustness: z.array(z.record(z.string(), z.unknown())).optional(),
    runtime: z.object({
      slope_ms_per_alert: z.number(),
      intercept_ms: z.number(),
      r_squared: z.number(),
      mean_throughput_alerts_per_ms: z.number(),
      throughput_variation: z.number(),
      repetitions: z.number(),
      preparation_time_ms: z.number(),
    }).passthrough().optional(),
    isolation_forest: z.object({
      evaluation_population: z.string(),
      refit_performed: z.boolean(),
      model_version: z.string().nullable().optional(),
      meta_alert_count: z.number(),
      score_min: z.number().nullable(),
      score_max: z.number().nullable(),
      score_mean: z.number().nullable(),
      decision_distribution: z.record(z.string(), z.number()),
      action_distribution: z.record(z.string(), z.number()),
    }).passthrough().optional(),
    structural_silhouette: z.object({
      is_calculable: z.boolean(),
      uncalculable_reason: z.string().nullable().optional(),
      observed_silhouette: z.number().nullable().optional(),
      random_mean: z.number().nullable().optional(),
      observed_percentile: z.number().nullable().optional(),
      z_score: z.number().nullable().optional(),
      empirical_p_value: z.number().nullable().optional(),
      n_valid_permutations: z.number().optional(),
      null_scores: z.array(z.number()).optional(),
      null_histogram: z.object({ bin_edges: z.array(z.number()).min(2), counts: z.array(z.number().int().nonnegative()).min(1) }).optional(),
    }).passthrough().optional(),
  }).passthrough().default({}),
});

export type EvaluationStatus = z.infer<typeof EvaluationStatusSchema>;

export const TimeseriesPointSchema = z.object({
  timestamp: z.string(),
  raw_alerts: z.number(),
  meta_alerts: z.number(),
});

export const TimeseriesSchema = z.array(TimeseriesPointSchema);

export type TimeseriesData = z.infer<typeof TimeseriesSchema>;

export const SystemInfoSchema = z.object({
  model_version: z.string(),
  tukey_threshold: z.number(),
  random_state: z.number().nullable().optional(),
  feature_names: z.array(z.string()).default([]),
  base_delta_t_seconds: z.number(),
  adaptive: z.boolean(),
  source_mode: z.string(),
  durable_state_path: z.string(),
  raw_evidence_db_path: z.string().nullable().optional(),
  system_status: z.string(),
});

export type SystemInfo = z.infer<typeof SystemInfoSchema>;

const TraceMemberSchema = z.object({
  wazuh_alert_id: z.string(),
  resolved: z.boolean(),
  timestamp: z.string().nullable(),
  agent_id: z.string().nullable(),
  agent_name: z.string().nullable(),
  rule_id: z.string().nullable(),
  rule_description: z.string().nullable(),
  rule_group_primary: z.string().nullable(),
  source_index: z.string().nullable(),
  source_document_id: z.string().nullable(),
  source_mode: z.string().nullable(),
  canonical_fingerprint: z.string().nullable(),
});

export const TraceSchema = z.preprocess((input) => {
  if (!input || typeof input !== 'object') return input;
  const trace = input as Record<string, unknown>;
  const sourceIds = Array.isArray(trace.source_alert_ids) ? trace.source_alert_ids.filter((id): id is string => typeof id === 'string') : [];
  const legacyMembers = sourceIds.map((wazuh_alert_id) => ({ wazuh_alert_id, resolved: false, timestamp: null, agent_id: null, agent_name: null, rule_id: null, rule_description: null, rule_group_primary: null, source_index: null, source_document_id: null, source_mode: null, canonical_fingerprint: null }));
  return { ...trace, rule_group_primary: trace.rule_group_primary ?? trace.rule_group, feature_schema_version: trace.feature_schema_version ?? 'unavailable (legacy response)', score_calibration_version: trace.score_calibration_version ?? 'unavailable (legacy response)', source_total: trace.source_total ?? trace.count ?? sourceIds.length, resolved_total: trace.resolved_total ?? 0, unresolved_alert_ids: trace.unresolved_alert_ids ?? sourceIds, members: trace.members ?? legacyMembers };
}, z.object({
  meta_id: z.number(),
  agent_id: z.string(),
  rule_group_primary: z.string(),
  decision: z.string(),
  action: z.string(),
  model_version: z.string(),
  feature_schema_version: z.string(),
  score_calibration_version: z.string(),
  source_total: z.number().int().nonnegative(),
  resolved_total: z.number().int().nonnegative(),
  unresolved_alert_ids: z.array(z.string()),
  members: z.array(TraceMemberSchema),
}));

export type Trace = z.infer<typeof TraceSchema>;

export const IntegrationItemSchema = z.object({
  name: z.string().optional(),
  status: z.string(),
  detail: z.string().optional(),
});

export const IntegrationsSchema = z.record(z.string(), IntegrationItemSchema);

export type IntegrationsData = z.infer<typeof IntegrationsSchema>;
