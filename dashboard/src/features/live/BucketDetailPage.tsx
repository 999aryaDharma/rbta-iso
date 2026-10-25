import { useQuery, keepPreviousData } from '@tanstack/react-query';
import { useParams, useNavigate, useSearchParams } from 'react-router-dom';
import { fetchBuckets, fetchBucketRawAlerts } from '@/api/dashboard';
import { ApiError } from '@/api/client';
import { PageHeader } from '@/components/shared/PageHeader';
import { formatDateTime, formatNumber } from '@/lib/formatters';
import { TERMS } from '@/lib/labels';
import { Banner } from '@cloudflare/kumo/components/banner';
import { Button } from '@cloudflare/kumo/components/button';
import { Badge } from '@cloudflare/kumo/components/badge';
import { Table } from '@cloudflare/kumo/components/table';
import { Pagination } from '@cloudflare/kumo/components/pagination';
import { ArrowLeft } from '@phosphor-icons/react';

const BUCKET_PAGE_SIZE = 20;

function ruleDescription(description: string, ruleId: string) {
  return description.trim() || `Rule ${ruleId}`;
}

function finalizedHint(message: string): number | null {
  try {
    const parsed = JSON.parse(message) as { detail?: unknown; finalized_meta_id?: unknown };
    return typeof parsed.finalized_meta_id === 'number' ? parsed.finalized_meta_id : null;
  } catch {
    return null;
  }
}

export function BucketDetailPage() {
  const { agentId = '', ruleGroup = '' } = useParams();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const page = Math.max(1, Number(searchParams.get('page') || 1));
  const runId = searchParams.get('run_id');

  const withRunId = (path: string) =>
    runId ? `${path}${path.includes('?') ? '&' : '?'}run_id=${encodeURIComponent(runId)}` : path;

  const bucketKey = `${agentId} · ${ruleGroup}`;

  const bucketsQuery = useQuery({
    queryKey: ['buckets', runId || 'live'],
    queryFn: () => fetchBuckets(runId || undefined),
    staleTime: 5000,
  });
  const bucket = bucketsQuery.data?.find(
    (b) => b.agent_id === agentId && b.rule_group_primary === ruleGroup,
  );

  const membersQuery = useQuery({
    queryKey: ['bucket-raw-alerts', agentId, ruleGroup, page, runId || 'live'],
    queryFn: () =>
      fetchBucketRawAlerts(agentId, ruleGroup, {
        page,
        page_size: BUCKET_PAGE_SIZE,
        run_id: runId || undefined,
      }),
    placeholderData: keepPreviousData,
    staleTime: 5000,
    retry: false,
  });

  const goneFinalizedId =
    membersQuery.error instanceof ApiError && membersQuery.error.status === 404
      ? finalizedHint(membersQuery.error.message)
      : null;

  const setPage = (next: number) => {
    const params = new URLSearchParams(searchParams);
    params.set('page', String(next));
    setSearchParams(params);
  };

  return (
    <>
      <PageHeader
        breadcrumbs={['Operasi', { label: 'Pemantauan live', href: '/live' }, bucketKey]}
        title={`Kelompok ${bucketKey}`}
        description="Alert dalam kelompok yang masih terbuka. Isinya bertambah saat alert baru masuk, sampai kelompok ditutup menjadi meta-alert."
        actions={
          <Button variant="ghost" size="sm" onClick={() => navigate(withRunId('/live'))}>
            <ArrowLeft size={14} className="mr-1" /> Kembali ke pemantauan live
          </Button>
        }
      />

      <div className="px-6 py-8 lg:px-10 space-y-6">
        {bucket && (
          <div className="flex flex-wrap items-center gap-x-6 gap-y-3 rounded-xl border border-kumo-hairline bg-kumo-canvas px-6 py-4 text-xs shadow-xs">
            <span className="inline-flex flex-col gap-1">
              <Badge variant="secondary">Masih bertambah</Badge>
              {bucket.meta_id != null && (
                <span className="font-mono text-[11px] text-kumo-subtle">akan menjadi meta-alert #{bucket.meta_id}</span>
              )}
            </span>
            <div>
              <p className="font-mono font-bold text-kumo-strong text-lg leading-none">
                {formatNumber(bucket.alert_count)}
              </p>
              <p className="text-kumo-subtle mt-1">Alert dalam kelompok</p>
            </div>
            <div>
              <p className="font-mono text-kumo-default">{formatDateTime(bucket.start_time)}</p>
              <p className="text-kumo-subtle mt-1">Mulai dikelompokkan</p>
            </div>
            <div>
              <p className="font-mono font-semibold text-kumo-default">
                {bucket.max_severity} / 15
              </p>
              <p className="text-kumo-subtle mt-1">Keparahan maks.</p>
            </div>
            {bucket.agent_name && (
              <div>
                <p className="font-mono text-kumo-default">{bucket.agent_name}</p>
                <p className="text-kumo-subtle mt-1">Nama agen</p>
              </div>
            )}
          </div>
        )}

        {membersQuery.isError && (
          <Banner
            variant="alert"
            size="sm"
            title={
              goneFinalizedId != null
                ? `Kelompok ini sudah ditutup menjadi meta-alert #${goneFinalizedId}.`
                : 'Kelompok tidak lagi terbuka.'
            }
            description={
              goneFinalizedId != null
                ? 'Alert dalam kelompok ini kini menjadi bukti meta-alert tersebut; buka halaman detailnya.'
                : 'Kelompok sudah ditutup atau belum pernah ada. Kembali ke pemantauan live untuk melihat kelompok yang masih terbuka.'
            }
          />
        )}
        {goneFinalizedId != null && (
          <div>
            <Button
              variant="primary"
              size="sm"
              onClick={() => navigate(withRunId(`/meta-alerts/${goneFinalizedId}`))}
            >
              Buka meta-alert #{goneFinalizedId}
            </Button>
          </div>
        )}

        {membersQuery.data && membersQuery.data.unresolved_alert_ids.length > 0 && (
          <Banner
            variant="alert"
            size="sm"
            title={`${membersQuery.data.resolved_total} dari ${membersQuery.data.source_total} alert asli tersedia.`}
            description={`${membersQuery.data.unresolved_alert_ids.length} alert asli belum tersimpan lokal: ${membersQuery.data.unresolved_alert_ids.join(', ')}`}
          />
        )}

        <div className="rounded-xl border border-kumo-hairline bg-kumo-canvas shadow-xs overflow-hidden">
          <div className="px-6 py-4 border-b border-kumo-hairline flex items-center justify-between">
            <div>
              <h2 className="text-sm font-semibold text-kumo-strong">
                {TERMS.bucketMembers} ({membersQuery.data ? formatNumber(membersQuery.data.filtered_total) : '…'})
              </h2>
              <p className="text-xs text-kumo-subtle mt-0.5">
                Urutan kedatangan. Baris bukan bukti serangan.
              </p>
            </div>
            {membersQuery.isFetching && (
              <p role="status" className="text-xs text-kumo-subtle font-mono">Memperbarui…</p>
            )}
          </div>
          <Table>
            <Table.Header>
              <Table.Row className="bg-kumo-recessed/50 text-[11px] uppercase tracking-wider">
                <Table.Head>Waktu</Table.Head>
                <Table.Head>ID alert Wazuh</Table.Head>
                <Table.Head>Deskripsi deteksi</Table.Head>
                <Table.Head className="text-right">Level</Table.Head>
                <Table.Head>Kategori aturan (Rule Group)</Table.Head>
                <Table.Head>IP sumber</Table.Head>
                <Table.Head>Taktik MITRE</Table.Head>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {(membersQuery.data?.items ?? []).map((a) => (
                <Table.Row
                  key={a.wazuh_alert_id}
                  onClick={() =>
                    navigate(
                      withRunId(
                        `/live/buckets/${encodeURIComponent(agentId)}/${encodeURIComponent(ruleGroup)}/raw-alerts/${encodeURIComponent(a.wazuh_alert_id)}`,
                      ),
                    )
                  }
                  className="hover:bg-kumo-recessed/40 transition-colors text-xs cursor-pointer"
                >
                  <Table.Cell className="font-mono text-kumo-subtle">{formatDateTime(a.timestamp)}</Table.Cell>
                  <Table.Cell className="font-mono text-kumo-default truncate max-w-[140px]">
                    {a.wazuh_alert_id}
                  </Table.Cell>
                  <Table.Cell>
                    <span className="font-medium text-kumo-strong">
                      {ruleDescription(a.rule_description, a.rule_id)}
                    </span>
                    <span className="block font-mono text-[11px] text-kumo-subtle">Rule ID: {a.rule_id}</span>
                  </Table.Cell>
                  <Table.Cell className="text-right font-mono font-bold text-kumo-strong">
                    {a.rule_level}
                  </Table.Cell>
                  <Table.Cell className="font-mono text-kumo-default">{a.rule_group_primary}</Table.Cell>
                  <Table.Cell className="font-mono text-kumo-subtle">{a.srcip || '-'}</Table.Cell>
                  <Table.Cell>
                    {a.mitre_tactics && a.mitre_tactics.length > 0 ? (
                      <Badge variant="secondary">{a.mitre_tactics.join(', ')}</Badge>
                    ) : (
                      <span className="text-kumo-subtle">Tidak ada</span>
                    )}
                  </Table.Cell>
                </Table.Row>
              ))}
              {membersQuery.data && membersQuery.data.items.length === 0 && (
                <Table.Row>
                  <Table.Cell colSpan={7} className="py-12 text-center text-xs text-kumo-subtle font-mono">
                    Belum ada alert dalam kelompok ini yang dapat ditampilkan.
                  </Table.Cell>
                </Table.Row>
              )}
            </Table.Body>
          </Table>

          {membersQuery.data && membersQuery.data.filtered_total > BUCKET_PAGE_SIZE && (
            <div className="px-6 py-4 border-t border-kumo-hairline bg-kumo-recessed/20">
              <Pagination
                page={page}
                setPage={setPage}
                perPage={BUCKET_PAGE_SIZE}
                totalCount={membersQuery.data.filtered_total}
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
