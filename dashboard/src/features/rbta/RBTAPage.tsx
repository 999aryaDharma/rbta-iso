import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { usePollingQuery } from '@/hooks/usePolling';
import { fetchAgents, fetchBuckets } from '@/api/dashboard';
import { MetricCard } from '@/components/shared/MetricCard';
import { PageHeader } from '@/components/shared/PageHeader';
import { formatNumber, formatSeconds, formatDateTime } from '@/lib/formatters';
import { Table } from '@cloudflare/kumo/components/table';
import { Badge } from '@cloudflare/kumo/components/badge';
import { Pagination } from '@cloudflare/kumo/components/pagination';

const PAGE_SIZE = 10;

export function RBTAPage() {
  const [searchParams] = useSearchParams();
  const runId = searchParams.get('run_id');
  const [agentPage, setAgentPage] = useState(1);
  const [bucketPage, setBucketPage] = useState(1);

  const { data: agents = [] } = usePollingQuery(['agents', runId || 'live'], () => fetchAgents(runId || undefined), 3000);
  const { data: buckets = [] } = usePollingQuery(['buckets', runId || 'live'], () => fetchBuckets(runId || undefined), 3000);

  const activeAgents = agents.length;
  const warmedUp = agents.filter((a) => a.is_warmed_up).length;
  const seenAlerts = agents.reduce((acc, a) => acc + a.event_count, 0);
  const activeBuckets = buckets.length;

  const paginatedAgents = agents.slice((agentPage - 1) * PAGE_SIZE, agentPage * PAGE_SIZE);
  const paginatedBuckets = buckets.slice((bucketPage - 1) * PAGE_SIZE, bucketPage * PAGE_SIZE);

  return (
    <>
      <PageHeader
        breadcrumbs={['Security Analytics', 'RBTA Engine']}
        title="RBTA Aggregation Engine Telemetry"
        description="Real-time agent temporal state tracking, dynamic window adaptation (Δt), and active in-memory buckets"
      />

      <div className="px-6 py-8 lg:px-10 space-y-8">
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-5">
          <MetricCard label="Active Agents" value={formatNumber(activeAgents)} sub="Monitored host agents" />
          <MetricCard label="Warmed-up Agents" value={formatNumber(warmedUp)} sub="Baseline calibrated" />
          <MetricCard label="Seen Alerts" value={formatNumber(seenAlerts)} sub="Total incoming raw events" />
          <MetricCard label="Open Active Buckets" value={formatNumber(activeBuckets)} sub="In-flight aggregation windows" />
        </div>

        <div className="rounded-xl border border-kumo-hairline bg-kumo-canvas shadow-xs overflow-hidden">
          <div className="px-6 py-4 border-b border-kumo-hairline flex items-center justify-between">
            <div>
              <h2 className="text-sm font-semibold text-kumo-strong">
                Agent Temporal States ({agents.length})
              </h2>
              <p className="text-xs text-kumo-subtle mt-0.5">
                Dynamic inter-arrival timing, exponential moving averages, and adaptive Δt windows
              </p>
            </div>
          </div>
          <Table>
            <Table.Header>
              <Table.Row className="bg-kumo-recessed/50 text-[11px] uppercase tracking-wider">
                <Table.Head>Agent ID</Table.Head>
                <Table.Head>Name</Table.Head>
                <Table.Head className="text-right">Events</Table.Head>
                <Table.Head className="text-center">Warmup</Table.Head>
                <Table.Head className="text-right">Baseline Gap</Table.Head>
                <Table.Head className="text-right">EMA Gap</Table.Head>
                <Table.Head className="text-right">Base Δt</Table.Head>
                <Table.Head className="text-right">Current Δt</Table.Head>
                <Table.Head className="text-right">Buckets</Table.Head>
                <Table.Head className="text-center">Status</Table.Head>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {paginatedAgents.map((a) => (
                <Table.Row key={a.agent_id} className="hover:bg-kumo-recessed/40 transition-colors text-xs">
                  <Table.Cell className="font-mono font-semibold text-kumo-strong">{a.agent_id}</Table.Cell>
                  <Table.Cell className="font-medium text-kumo-default">{a.agent_name}</Table.Cell>
                  <Table.Cell className="text-right font-mono text-kumo-default">{formatNumber(a.event_count)}</Table.Cell>
                  <Table.Cell className="text-center font-mono text-kumo-subtle">
                    {a.warmup_progress}/{a.warmup_required}
                  </Table.Cell>
                  <Table.Cell className="text-right font-mono text-kumo-subtle">{formatSeconds(a.baseline_gap_seconds)}</Table.Cell>
                  <Table.Cell className="text-right font-mono text-kumo-subtle">{formatSeconds(a.ema_gap_seconds)}</Table.Cell>
                  <Table.Cell className="text-right font-mono text-kumo-subtle">{formatSeconds(a.base_delta_t_seconds)}</Table.Cell>
                  <Table.Cell className="text-right font-mono font-bold text-kumo-strong">
                    {formatSeconds(a.current_delta_t_seconds)}
                  </Table.Cell>
                  <Table.Cell className="text-right font-mono font-semibold text-kumo-strong">{a.active_bucket_count}</Table.Cell>
                  <Table.Cell className="text-center">
                    <Badge variant={a.is_warmed_up ? 'success' : 'secondary'}>
                      {a.status}
                    </Badge>
                  </Table.Cell>
                </Table.Row>
              ))}
              {agents.length === 0 && (
                <Table.Row>
                  <Table.Cell colSpan={10} className="py-12 text-center text-xs text-kumo-subtle font-mono">
                    No agent states active yet.
                  </Table.Cell>
                </Table.Row>
              )}
            </Table.Body>
          </Table>

          {agents.length > PAGE_SIZE && (
            <div className="px-6 py-4 border-t border-kumo-hairline bg-kumo-recessed/20">
              <Pagination
                page={agentPage}
                setPage={setAgentPage}
                perPage={PAGE_SIZE}
                totalCount={agents.length}
              >
                <Pagination.Info />
                <Pagination.Separator />
                <Pagination.Controls />
              </Pagination>
            </div>
          )}
        </div>

        <div className="rounded-xl border border-kumo-hairline bg-kumo-canvas shadow-xs overflow-hidden">
          <div className="px-6 py-4 border-b border-kumo-hairline flex items-center justify-between">
            <div>
              <h2 className="text-sm font-semibold text-kumo-strong">
                Active In-Flight Aggregation Buckets ({buckets.length})
              </h2>
              <p className="text-xs text-kumo-subtle mt-0.5">
                Open temporal buffers awaiting expiration timeout before Isolation Forest evaluation
              </p>
            </div>
          </div>
          <Table>
            <Table.Header>
              <Table.Row className="bg-kumo-recessed/50 text-[11px] uppercase tracking-wider">
                <Table.Head>Agent / Host</Table.Head>
                <Table.Head>Primary Rule Group</Table.Head>
                <Table.Head>Window Opened At</Table.Head>
                <Table.Head>Last Alert Time</Table.Head>
                <Table.Head className="text-right">Accumulated Events</Table.Head>
                <Table.Head className="text-right">Max Severity</Table.Head>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {paginatedBuckets.map((b, idx) => (
                <Table.Row key={`${b.agent_id}-${b.rule_group_primary}-${idx}`} className="hover:bg-kumo-recessed/40 transition-colors text-xs">
                  <Table.Cell className="font-mono text-kumo-default">{b.agent_name ? `${b.agent_name} (${b.agent_id})` : b.agent_id}</Table.Cell>
                  <Table.Cell className="font-mono font-medium text-kumo-strong">{b.rule_group_primary}</Table.Cell>
                  <Table.Cell className="text-kumo-subtle">{formatDateTime(b.start_time)}</Table.Cell>
                  <Table.Cell className="text-kumo-subtle">{formatDateTime(b.end_time)}</Table.Cell>
                  <Table.Cell className="text-right font-mono font-bold text-kumo-strong">{b.alert_count}</Table.Cell>
                  <Table.Cell className="text-right font-mono font-semibold text-kumo-default">{b.max_severity} / 15</Table.Cell>
                </Table.Row>
              ))}
              {buckets.length === 0 && (
                <Table.Row>
                  <Table.Cell colSpan={6} className="py-12 text-center text-xs text-kumo-subtle font-mono">
                    No open buckets currently active in runtime memory.
                  </Table.Cell>
                </Table.Row>
              )}
            </Table.Body>
          </Table>

          {buckets.length > PAGE_SIZE && (
            <div className="px-6 py-4 border-t border-kumo-hairline bg-kumo-recessed/20">
              <Pagination
                page={bucketPage}
                setPage={setBucketPage}
                perPage={PAGE_SIZE}
                totalCount={buckets.length}
              >
                <Pagination.Info />
                <Pagination.Separator />
                <Pagination.Controls />
              </Pagination>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
