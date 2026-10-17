import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useParams, useNavigate, useSearchParams } from 'react-router-dom';
import { fetchRawAlert } from '@/api/rawAlerts';
import { fetchMetaAlertTrace } from '@/api/metaAlerts';
import { PageHeader } from '@/components/shared/PageHeader';
import { formatDateTime } from '@/lib/formatters';
import { Banner } from '@cloudflare/kumo/components/banner';
import { Button } from '@cloudflare/kumo/components/button';
import { Copy, Check, ArrowLeft, CaretLeft, CaretRight } from '@phosphor-icons/react';

export function RawAlertDetailPage() {
  const { metaId, alertId } = useParams();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const runId = searchParams.get('run_id');
  const [copied, setCopied] = useState(false);

  const withRunId = React.useCallback(
    (path: string) => (runId ? `${path}${path.includes('?') ? '&' : '?'}run_id=${encodeURIComponent(runId)}` : path),
    [runId]
  );

  const numericMetaId = metaId ? Number(metaId) : null;

  const { data, isError } = useQuery({
    queryKey: ['raw-alert', alertId, runId || 'live'],
    queryFn: () => fetchRawAlert(alertId as string, runId || undefined),
    enabled: Boolean(alertId),
    retry: false,
  });

  const { data: trace } = useQuery({
    queryKey: ['meta-alert-trace', numericMetaId, runId || 'live'],
    queryFn: () => (numericMetaId ? fetchMetaAlertTrace(numericMetaId, runId || undefined) : null),
    enabled: Boolean(numericMetaId),
  });

  const sourceIds = trace?.members.map((member) => member.wazuh_alert_id) || [];
  const currentIndex = alertId ? sourceIds.indexOf(alertId) : -1;
  const prevId = currentIndex > 0 ? sourceIds[currentIndex - 1] : null;
  const nextId = currentIndex >= 0 && currentIndex < sourceIds.length - 1 ? sourceIds[currentIndex + 1] : null;

  // Shortcut keyboard [ dan ] untuk navigasi
  React.useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement;
      if (['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName) || target.isContentEditable) {
        return;
      }
      if (e.key === '[' && prevId && metaId) {
        e.preventDefault();
        navigate(withRunId(`/meta-alerts/${metaId}/raw-alerts/${encodeURIComponent(prevId)}`));
      } else if (e.key === ']' && nextId && metaId) {
        e.preventDefault();
        navigate(withRunId(`/meta-alerts/${metaId}/raw-alerts/${encodeURIComponent(nextId)}`));
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [prevId, nextId, metaId, withRunId, navigate]);

  const handleCopy = () => {
    if (!data) return;
    navigator.clipboard.writeText(JSON.stringify(data, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <>
      <PageHeader
        breadcrumbs={
          metaId
            ? ['Analisis', 'Daftar meta-alert', `#${metaId}`, 'Alert asli', String(alertId)]
            : ['Analisis', 'Alert asli', String(alertId)]
        }
        title="Detail alert asli"
        description={`ID alert Wazuh: ${alertId}`}
        actions={
          <div className="flex items-center gap-2">
            {metaId && sourceIds.length > 0 && (
              <div className="flex items-center gap-1 mr-2">
                <Button
                  variant="ghost"
                  size="sm"
                  disabled={!prevId}
                  onClick={() => prevId && navigate(withRunId(`/meta-alerts/${metaId}/raw-alerts/${encodeURIComponent(prevId)}`))}
                  title="Alert sebelumnya ([)"
                >
                  <CaretLeft size={14} className="mr-0.5" /> Sebelumnya
                </Button>

                <span className="text-xs font-mono px-2 text-kumo-subtle">
                  {currentIndex >= 0 ? `${currentIndex + 1} / ${sourceIds.length}` : '-'}
                </span>

                <Button
                  variant="ghost"
                  size="sm"
                  disabled={!nextId}
                  onClick={() => nextId && navigate(withRunId(`/meta-alerts/${metaId}/raw-alerts/${encodeURIComponent(nextId)}`))}
                  title="Alert berikutnya (])"
                >
                  Berikutnya <CaretRight size={14} className="ml-0.5" />
                </Button>
              </div>
            )}

            {data && (
              <Button
                variant="secondary"
                size="sm"
                onClick={handleCopy}
              >
                {copied ? <Check size={14} className="text-emerald-500 mr-1" /> : <Copy size={14} className="mr-1" />}
                {copied ? 'Tersalin' : 'Salin JSON'}
              </Button>
            )}

            {metaId && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => navigate(withRunId(`/meta-alerts/${metaId}/raw-alerts`))}
              >
                <ArrowLeft size={14} className="mr-1" /> Kembali
              </Button>
            )}
          </div>
        }
      />

      <div className="px-6 py-8 lg:px-10 space-y-8">
        {isError && (
          <Banner
            variant="alert"
            size="sm"
            title="Data alert asli tidak tersedia"
            description={`Alert ini tercatat di meta-alert #${metaId}, tapi datanya tidak tersimpan lokal.`}
          />
        )}

        {data && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="space-y-6">
              <div className="p-6 rounded-xl border border-kumo-hairline bg-kumo-canvas shadow-xs">
                <h3 className="font-semibold text-xs uppercase tracking-wider text-kumo-strong mb-4 pb-3 border-b border-kumo-hairline">Identitas & asal data</h3>
                <dl className="space-y-3 text-xs">
                  <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40"><dt className="text-kumo-subtle font-medium">ID alert Wazuh:</dt> <dd className="font-mono font-semibold text-kumo-strong">{data.wazuh_alert_id}</dd></div>
                  <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40"><dt className="text-kumo-subtle font-medium">Waktu (WITA):</dt> <dd className="font-mono text-kumo-default">{formatDateTime(data.timestamp)}</dd></div>
                  <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40"><dt className="text-kumo-subtle font-medium">Sumber data:</dt> <dd className="font-mono text-kumo-default">{data.source_mode || 'LIVE'}</dd></div>
                  <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40"><dt className="text-kumo-subtle font-medium">Agen:</dt> <dd className="text-kumo-default font-medium">{data.agent_name} ({data.agent_id}) · Kepentingan aset: {data.agent_criticality}</dd></div>
                  {data.source_index && (
                    <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40"><dt className="text-kumo-subtle font-medium">Indeks sumber:</dt> <dd className="font-mono text-kumo-default">{data.source_index}</dd></div>
                  )}
                  {data.source_document_id && (
                    <div className="flex justify-between items-center py-1"><dt className="text-kumo-subtle font-medium">ID dokumen:</dt> <dd className="font-mono text-kumo-default truncate max-w-xs">{data.source_document_id}</dd></div>
                  )}
                </dl>
              </div>

              <div className="p-6 rounded-xl border border-kumo-hairline bg-kumo-canvas shadow-xs">
                <h3 className="font-semibold text-xs uppercase tracking-wider text-kumo-strong mb-4 pb-3 border-b border-kumo-hairline">Aturan & deskripsi deteksi</h3>
                <dl className="space-y-3 text-xs">
                  <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40"><dt className="text-kumo-subtle font-medium">ID rule:</dt> <dd className="font-mono font-semibold text-kumo-default">{data.rule_id}</dd></div>
                  <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40"><dt className="text-kumo-subtle font-medium">Tingkat keparahan:</dt> <dd className="font-mono font-bold text-kumo-strong">{data.rule_level} / 15</dd></div>
                  <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40"><dt className="text-kumo-subtle font-medium">Kategori aturan utama:</dt> <dd className="font-mono text-kumo-default">{data.rule_group_primary}</dd></div>
                  <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40"><dt className="text-kumo-subtle font-medium">Semua kategori aturan:</dt> <dd className="font-mono text-kumo-default">{data.rule_groups_all.join(', ') || data.rule_group_primary}</dd></div>
                  <div className="pt-1"><dt className="text-kumo-subtle font-medium">Deskripsi:</dt> <dd className="mt-2 p-3.5 rounded-lg border border-kumo-hairline bg-kumo-recessed/30 text-xs text-kumo-default leading-relaxed">{data.rule_description}</dd></div>
                </dl>
              </div>

              <div className="p-6 rounded-xl border border-kumo-hairline bg-kumo-canvas shadow-xs">
                <h3 className="font-semibold text-xs uppercase tracking-wider text-kumo-strong mb-4 pb-3 border-b border-kumo-hairline">Jaringan & konteks MITRE ATT&CK</h3>
                <dl className="space-y-3 text-xs">
                  <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40"><dt className="text-kumo-subtle font-medium">IP sumber:</dt> <dd className="font-mono text-kumo-default font-semibold">{data.srcip || '-'}</dd></div>
                  <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40"><dt className="text-kumo-subtle font-medium">Lokasi log:</dt> <dd className="font-mono text-kumo-default">{data.location || '-'}</dd></div>
                  <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40"><dt className="text-kumo-subtle font-medium">Decoder Wazuh:</dt> <dd className="font-mono text-kumo-default">{data.decoder || '-'}</dd></div>
                  <div className="flex justify-between items-center py-1.5 border-b border-kumo-hairline/40"><dt className="text-kumo-subtle font-medium">Taktik MITRE:</dt> <dd className="font-mono text-kumo-default">{data.mitre_tactics.join(', ') || 'Tidak ada'}</dd></div>
                  <div className="flex justify-between items-center py-1"><dt className="text-kumo-subtle font-medium">Teknik MITRE:</dt> <dd className="font-mono text-kumo-default">{data.mitre_techniques.join(', ') || 'Tidak ada'}</dd></div>
                </dl>
              </div>
            </div>

            <div className="space-y-6">
              {data.full_log && (
                <div className="p-6 rounded-xl border border-kumo-hairline bg-kumo-canvas shadow-xs">
                  <h3 className="font-semibold text-xs uppercase tracking-wider text-kumo-strong mb-3 pb-2 border-b border-kumo-hairline">Isi log lengkap</h3>
                  <pre className="text-xs font-mono p-3.5 rounded-lg border border-kumo-hairline bg-kumo-recessed/30 text-kumo-default overflow-auto max-h-48 whitespace-pre-wrap leading-relaxed">
                    {data.full_log}
                  </pre>
                </div>
              )}

              <div className="p-6 rounded-xl border border-kumo-hairline bg-kumo-canvas shadow-xs">
                <div className="flex items-center justify-between mb-3 pb-2 border-b border-kumo-hairline">
                  <h3 className="font-semibold text-xs uppercase tracking-wider text-kumo-strong">Data lengkap (JSON)</h3>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-kumo-hairline bg-kumo-recessed text-kumo-subtle">Bukti asli (tidak diubah)</span>
                </div>
                <pre className="text-xs font-mono p-4 rounded-lg border border-kumo-hairline bg-kumo-recessed/30 text-kumo-default overflow-auto max-h-[500px] leading-relaxed">
                  {JSON.stringify(data, null, 2)}
                </pre>
              </div>
            </div>
          </div>
        )}
      </div>
    </>
  );
}
