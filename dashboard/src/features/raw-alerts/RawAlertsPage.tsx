import { useQuery, useQueryClient, keepPreviousData } from '@tanstack/react-query';
import { useParams, useNavigate, useSearchParams } from 'react-router-dom';
import { fetchMetaAlertRawAlerts } from '@/api/rawAlerts';
import { PageHeader } from '@/components/shared/PageHeader';
import { formatDateTime } from '@/lib/formatters';
import { Banner } from '@cloudflare/kumo/components/banner';
import { Button } from '@cloudflare/kumo/components/button';
import { Badge } from '@cloudflare/kumo/components/badge';
import { InputGroup } from '@cloudflare/kumo/components/input-group';
import { Table } from '@cloudflare/kumo/components/table';
import { Pagination } from '@cloudflare/kumo/components/pagination';
import { MagnifyingGlass, ArrowLeft } from '@phosphor-icons/react';
import { useEffect, useState } from 'react';

const RAW_ALERT_PAGE_SIZE = 20;

function ruleDescription(description: string, ruleId: string) {
  return description.trim() || `Rule ${ruleId}`;
}

export function RawAlertsPage() {
  const { metaId } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const page = Number(searchParams.get('page') || 1);
  const urlSearch = searchParams.get('search') || '';
  const runId = searchParams.get('run_id');
  const id = Number(metaId);
  const [localSearch, setLocalSearch] = useState(urlSearch);

  const withRunId = (path: string) => (runId ? `${path}${path.includes('?') ? '&' : '?'}run_id=${encodeURIComponent(runId)}` : path);

  // Sinkronkan pencarian lokal dari URL
  useEffect(() => { setLocalSearch(urlSearch); }, [urlSearch]);

  // Debounce pencarian
  useEffect(() => {
    const timer = setTimeout(() => {
      if (localSearch !== urlSearch) {
        const params = new URLSearchParams(searchParams);
        if (localSearch) params.set('search', localSearch);
        else params.delete('search');
        params.set('page', '1');
        setSearchParams(params);
      }
    }, 300);
    return () => clearTimeout(timer);
  }, [localSearch, urlSearch, searchParams, setSearchParams]);

  const { data, isFetching, isPlaceholderData } = useQuery({
    queryKey: ['raw-alerts', id, page, urlSearch, runId || 'live'],
    queryFn: () =>
      fetchMetaAlertRawAlerts(id, {
        page,
        page_size: RAW_ALERT_PAGE_SIZE,
        search: urlSearch || undefined,
        run_id: runId || undefined,
      }),
    placeholderData: keepPreviousData,
    staleTime: 5000,
  });

  // Prefetch halaman berikutnya
  useEffect(() => {
    const totalPages = data ? Math.ceil(data.filtered_total / RAW_ALERT_PAGE_SIZE) || 1 : 1;
    if (data && page < totalPages) {
      queryClient.prefetchQuery({
        queryKey: ['raw-alerts', id, page + 1, urlSearch, runId || 'live'],
        queryFn: () =>
          fetchMetaAlertRawAlerts(id, {
            page: page + 1,
            page_size: RAW_ALERT_PAGE_SIZE,
            search: urlSearch || undefined,
            run_id: runId || undefined,
          }),
        staleTime: 5000,
      });
    }
  }, [data, page, urlSearch, runId, queryClient, id]);

  return (
    <>
      <PageHeader
        breadcrumbs={['Analisis', { label: 'Daftar meta-alert', href: '/meta-alerts' }, { label: `#${id}`, href: `/meta-alerts/${id}` }, 'Alert asli']}
        title={`Alert asli dalam meta-alert #${id}`}
        description="Kejadian log keamanan yang digabung ke dalam meta-alert ini"
        actions={
          <Button
            variant="ghost"
            size="sm"
            onClick={() => navigate(withRunId(`/meta-alerts/${id}`))}
          >
            <ArrowLeft size={14} className="mr-1" /> Kembali ke meta-alert
          </Button>
        }
      />

      <div className="px-6 py-8 lg:px-10 space-y-6">
        {data && data.unresolved_alert_ids && data.unresolved_alert_ids.length > 0 && (
          <Banner
            variant="alert"
            size="sm"
            title={`${data.resolved_total} dari ${data.source_total} alert asli tersedia.`}
            description={`${data.unresolved_alert_ids.length} alert tercatat di meta-alert #${id}, tapi datanya tidak tersimpan lokal: ${data.unresolved_alert_ids.join(', ')}`}
          />
        )}

        <div className="p-5 rounded-xl border border-kumo-hairline bg-kumo-canvas shadow-xs flex flex-wrap items-center justify-between gap-4">
          <div className="w-full sm:w-80">
            <InputGroup>
              <InputGroup.Addon align="start"><MagnifyingGlass size={14} className="text-kumo-subtle" /></InputGroup.Addon>
              <InputGroup.Input
                placeholder="Cari ID alert, ID rule, deskripsi, IP…"
                value={localSearch}
                onChange={(e) => setLocalSearch(e.target.value)}
              />
            </InputGroup>
          </div>

          <div className="flex items-center gap-2 text-xs text-kumo-subtle">
            {isFetching && <span className="animate-pulse">Memperbarui…</span>}
            <span className="font-mono bg-kumo-recessed px-2.5 py-1 rounded border border-kumo-hairline text-kumo-strong font-medium">
              {data ? `Menampilkan ${data.filtered_total} dari ${data.source_total}` : 'Memuat…'}
            </span>
          </div>
        </div>

        <div className={`rounded-xl border border-kumo-hairline bg-kumo-canvas shadow-xs overflow-hidden transition-opacity ${isPlaceholderData ? 'opacity-70' : ''}`}>
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
              {data?.items.map((a) => (
                <Table.Row
                  key={a.wazuh_alert_id}
                  className="cursor-pointer hover:bg-kumo-recessed/40 transition-colors text-xs"
                  onClick={() =>
                    navigate(withRunId(`/meta-alerts/${id}/raw-alerts/${encodeURIComponent(a.wazuh_alert_id)}`))
                  }
                >
                  <Table.Cell className="text-xs font-mono text-kumo-subtle">{formatDateTime(a.timestamp)}</Table.Cell>
                  <Table.Cell className="font-mono text-xs font-semibold text-kumo-strong truncate max-w-[140px]">
                    {a.wazuh_alert_id}
                  </Table.Cell>
                  <Table.Cell className="max-w-[320px] text-xs text-kumo-default"><span title={ruleDescription(a.rule_description, a.rule_id)} className="line-clamp-2">{ruleDescription(a.rule_description, a.rule_id)}</span><div className="mt-1 font-mono text-[10px] text-kumo-subtle">Rule ID: {a.rule_id}</div></Table.Cell>
                  <Table.Cell className="text-xs text-right font-mono font-bold text-kumo-strong">{a.rule_level}</Table.Cell>
                  <Table.Cell className="max-w-[320px] text-xs text-kumo-default">{a.rule_group_primary}</Table.Cell>
                  <Table.Cell className="font-mono text-xs text-kumo-subtle">{a.srcip || '-'}</Table.Cell>
                  <Table.Cell className="text-xs">
                    {a.mitre_tactics && a.mitre_tactics.length > 0 ? (
                      <Badge variant="secondary">{a.mitre_tactics.join(', ')}</Badge>
                    ) : (
                      <span className="text-kumo-subtle text-[11px]">Tidak ada</span>
                    )}
                  </Table.Cell>
                </Table.Row>
              ))}
              {data && data.items.length === 0 && (
                <Table.Row>
                  <Table.Cell colSpan={7} className="py-12 text-center text-xs text-kumo-subtle font-mono">
                    Tidak ada alert asli yang cocok.
                  </Table.Cell>
                </Table.Row>
              )}
            </Table.Body>
          </Table>

          <div className="px-6 py-4 border-t border-kumo-hairline bg-kumo-recessed/20">
            <Pagination
              page={page}
              setPage={(p) => {
                const params = new URLSearchParams(searchParams);
                params.set('page', String(p));
                setSearchParams(params);
              }}
              perPage={RAW_ALERT_PAGE_SIZE}
              totalCount={data?.filtered_total ?? 0}
            >
              <Pagination.Info />
              <Pagination.Separator />
              <Pagination.Controls />
            </Pagination>
          </div>
        </div>
      </div>
    </>
  );
}
