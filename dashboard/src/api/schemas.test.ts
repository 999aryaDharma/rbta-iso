import { describe, it, expect } from 'vitest';
import {
  DashboardSummarySchema,
  AgentStateSchema,
  MetaAlertSchema,
  RawAlertSchema,
  ReplayStatusSchema,
  DatasetCatalogStatusSchema,
  SystemInfoSchema,
  TraceSchema,
} from './schemas';

describe('Zod v4 Schema Validation & Contract Integrity', () => {
  it('parses dataset catalog indexing progress', () => {
    const result = DatasetCatalogStatusSchema.parse({
      status: 'RUNNING', total_files: 142, completed_files: 38, failed_files: 0, invalid_files: 0,
      pending_files: 104, current_file: 'wazuh-alerts-4.x-2026.05.10.jsonl',
      last_error: null, errors: [], started_at_utc: '2026-09-07T10:00:00Z', completed_at_utc: null,
    });
    expect(result.completed_files).toBe(38);
    expect(result.pending_files).toBe(104);
  });
  it('parses valid dashboard summary without fabricated defaults', () => {
    const valid = {
      raw_alert_count: 100,
      meta_alert_count: 10,
      alert_reduction_rate_percent: 90.0,
      escalate_count: 2,
      digest_count: 3,
      suppress_count: 5,
      anomalies_detected: 2,
      critical_meta_count: 1,
      active_buckets_count: 4,
      source_mode: 'LIVE',
      system_status: 'RUNNING',
    };
    const result = DashboardSummarySchema.parse(valid);
    expect(result.system_status).toBe('RUNNING');
    expect(result.alert_reduction_rate_percent).toBe(90.0);
  });

  it('fails dashboard summary when required system_status is missing', () => {
    const invalid = {
      raw_alert_count: 100,
      meta_alert_count: 10,
      escalate_count: 2,
      digest_count: 3,
      suppress_count: 5,
      anomalies_detected: 2,
      critical_meta_count: 1,
      active_buckets_count: 4,
      source_mode: 'LIVE',
      // system_status sengaja dihilangkan
    };
    expect(() => DashboardSummarySchema.parse(invalid)).toThrow();
  });

  it('fails MetaAlert when required model_version or features are missing', () => {
    const invalid = {
      meta_id: 1,
      agent_id: 'agent-001',
      agent_name: 'prod-srv',
      rule_group_primary: 'ssh',
      start_time: '2026-08-29T10:00:00Z',
      end_time: '2026-08-29T10:15:00Z',
      alert_count: 5,
      max_severity: 10,
      seven_features: { max_severity: 10 },
      raw_model_score: -0.15,
      anomaly_score: 0.85,
      threshold_used: 0.65,
      decision: 'ESCALATE',
      action: 'DISPATCH',
      escalate: true,
      // model_version sengaja dihilangkan - TIDAK boleh default ke v1
    };
    expect(() => MetaAlertSchema.parse(invalid)).toThrow();
  });

  it('parses valid MetaAlert with exact 7 features and versions', () => {
    const valid = {
      meta_id: 1,
      agent_id: 'agent-001',
      agent_name: 'prod-srv',
      rule_group_primary: 'ssh',
      start_time: '2026-08-29T10:00:00Z',
      end_time: '2026-08-29T10:15:00Z',
      alert_count: 5,
      max_severity: 10,
      mitre_tactics: ['initial-access'],
      seven_features: {
        max_severity: 10,
        mitre_tactic_count: 1,
        critical_mitre_tactic_present: 0,
        alert_count_log: 1.609,
        rule_diversity_shannon: 0.0,
        severity_dispersion: 0.0,
        agent_criticality: 2,
      },
      raw_model_score: -0.15,
      anomaly_score: 0.85,
      threshold_used: 0.65,
      decision: 'ESCALATE',
      action: 'DISPATCH',
      escalate: true,
      model_version: 'rf-v2.1',
      feature_schema_version: '1.0',
      score_calibration_version: 'v1.1',
      source_alert_ids: ['alt-1', 'alt-2'],
    };
    const result = MetaAlertSchema.parse(valid);
    expect(result.model_version).toBe('rf-v2.1');
    expect(result.seven_features.max_severity).toBe(10);
  });

  it('fails AgentState when warmup metrics or delta_t are missing', () => {
    const invalid = {
      agent_id: '001',
      agent_name: 'test',
      event_count: 10,
      // warmup_required, base_delta_t_seconds sengaja dihilangkan
    };
    expect(() => AgentStateSchema.parse(invalid)).toThrow();
  });

  it('parses valid ReplayStatus and preserves exact speed contract', () => {
    const valid = {
      run_id: 'run-xyz-123',
      status: 'RUNNING',
      dataset: 'eval.jsonl',
      processed_count: 500,
      total_count: 1000,
      progress: 0.5,
      updated_at: '2026-08-29T12:00:00Z',
      current_event_time: '2026-08-29T12:00:00Z',
      wall_clock_elapsed_seconds: 12.5,
      speed: 'MAX',
      events_per_second: 40.0,
      model_version: 'eval-v1',
    };
    const result = ReplayStatusSchema.parse(valid);
    expect(result.speed).toBe('MAX');
    expect(result.status).toBe('RUNNING');
  });

  it('rejects a percentage in the normalized replay progress field', () => {
    expect(() => ReplayStatusSchema.parse({ run_id: null, status: 'RUNNING', dataset: 'x.jsonl', processed_count: 500, total_count: 1000, progress: 50, updated_at: '2026-08-29T12:00:00Z', current_event_time: null, wall_clock_elapsed_seconds: 1, speed: 'MAX', events_per_second: 1, model_version: 'v1' })).toThrow();
  });

  it('parses resolved and unresolved provenance members without a legacy rule_group alias', () => {
    const result = TraceSchema.parse({
      meta_id: 7, agent_id: '001', rule_group_primary: 'auth', decision: 'SUSPICIOUS', action: 'ESCALATE',
      model_version: 'frozen-v1', feature_schema_version: '7f-v1', score_calibration_version: 'tukey-v1',
      source_total: 2, resolved_total: 1, unresolved_alert_ids: ['missing'],
      members: [
        { wazuh_alert_id: 'found', resolved: true, timestamp: '2026-01-01T00:00:00Z', agent_id: '001', agent_name: 'host', rule_id: '5710', rule_description: 'SSH fail', rule_group_primary: 'auth', source_index: 'idx', source_document_id: 'doc', source_mode: 'REPLAY', canonical_fingerprint: 'a'.repeat(64) },
        { wazuh_alert_id: 'missing', resolved: false, timestamp: null, agent_id: null, agent_name: null, rule_id: null, rule_description: null, rule_group_primary: null, source_index: null, source_document_id: null, source_mode: null, canonical_fingerprint: null },
      ],
    });
    expect(result.resolved_total).toBe(1);
  });

  it('adapts the deployed legacy trace response into explicit unresolved members', () => {
    const trace = TraceSchema.parse({ meta_id: 9, agent_id: '001', rule_group: 'ssh', decision: 'SUSPICIOUS', action: 'ESCALATE', model_version: 'legacy-v1', source_alert_ids: ['a', 'b'], count: 2 });
    expect(trace.rule_group_primary).toBe('ssh');
    expect(trace.unresolved_alert_ids).toEqual(['a', 'b']);
    expect(trace.members).toHaveLength(2);
  });

  it('parses valid RawAlert with optional fields defaults', () => {
    const valid = {
      wazuh_alert_id: 'alt-999',
      timestamp: '2026-08-29T12:00:00Z',
      agent_id: '001',
      agent_name: 'db-master',
      rule_id: '5710',
      rule_level: 8,
      rule_group_primary: 'syslog',
      agent_criticality: 3,
    };
    const result = RawAlertSchema.parse(valid);
    expect(result.wazuh_alert_id).toBe('alt-999');
    expect(result.rule_description).toBe('');
    expect(result.mitre_tactics).toEqual([]);
  });

  it('parses valid SystemInfo with required durability and model configuration', () => {
    const valid = {
      model_version: 'iso-forest-v1.0',
      tukey_threshold: 0.672,
      base_delta_t_seconds: 900,
      adaptive: true,
      source_mode: 'REPLAY',
      durable_state_path: '/data/runtime/state.json',
      system_status: 'HEALTHY',
    };
    const result = SystemInfoSchema.parse(valid);
    expect(result.model_version).toBe('iso-forest-v1.0');
    expect(result.tukey_threshold).toBe(0.672);
  });
});
