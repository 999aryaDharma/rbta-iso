import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { fetchTelegramPayloads } from '@/api/replay';
import { Table } from '@cloudflare/kumo/components/table';
import { Badge } from '@cloudflare/kumo/components/badge';
import { Pagination } from '@cloudflare/kumo/components/pagination';
import { PaperPlaneRight, Copy, Check, ArrowClockwise } from '@phosphor-icons/react';
import { DialogRoot, Dialog, DialogTitle, DialogDescription, DialogClose } from '@cloudflare/kumo/components/dialog';
import type { TelegramPayload } from '@/api/schemas';
import { decisionLabel } from '@/lib/labels';
import { TelegramMessagePreview } from './TelegramMessagePreview';

const PAGE_SIZE = 10;

export function DeferredTelegramOutbox() {
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [selectedPayload, setSelectedPayload] = useState<TelegramPayload | null>(null);
  const { data, isLoading, refetch } = useQuery({
    queryKey: ['telegram-payloads'],
    queryFn: () => fetchTelegramPayloads(50),
    refetchInterval: 3000,
  });

  const handleCopy = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const payloads = data?.items || [];
  const totalCount = data?.total_count || 0;
  const paginatedPayloads = payloads.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  return (
    <div className="rounded-xl border border-kumo-hairline bg-kumo-canvas p-6 shadow-xs space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-4 pb-3 border-b border-kumo-hairline">
        <div className="flex items-center gap-3">
          <div className="w-6 h-6 rounded-md border border-kumo-hairline bg-kumo-recessed flex items-center justify-center text-kumo-strong">
            <PaperPlaneRight size={14} />
          </div>
          <span className="text-xs font-semibold uppercase tracking-wider text-kumo-strong">
            Pesan Telegram yang belum dikirim
          </span>
          <Badge variant="error">
            {totalCount} pesan 'perlu dicek segera'
          </Badge>
        </div>

        <div className="flex items-center gap-3">
          <span className="text-[11px] font-mono text-kumo-subtle">
            Berkas: <code className="bg-kumo-recessed px-1.5 py-0.5 rounded border border-kumo-hairline">telegram_escalate_payloads.txt</code>
          </span>
          <button
            type="button"
            onClick={() => refetch()}
            className="p-1 rounded text-kumo-subtle hover:text-kumo-default hover:bg-kumo-recessed transition-colors"
            title="Muat ulang antrean pesan"
          >
            <ArrowClockwise size={14} />
          </button>
        </div>
      </div>

      {isLoading ? (
        <div className="py-8 text-center text-xs text-kumo-subtle font-mono">
          Memuat pesan yang tercatat…
        </div>
      ) : payloads.length > 0 ? (
        <div className="min-w-0 rounded-lg border border-kumo-hairline bg-kumo-canvas shadow-xs">
          <Table className="w-full table-fixed">
            <Table.Header>
              <Table.Row className="bg-kumo-recessed/50 text-[11px] uppercase tracking-wider">
                <Table.Head>Waktu</Table.Head>
                <Table.Head>Nomor</Table.Head>
                <Table.Head>Level</Table.Head>
                <Table.Head>Kategori aturan & agen</Table.Head>
                <Table.Head>Skor / batas skor</Table.Head>
                <Table.Head>Isi pesan</Table.Head>
                <Table.Head className="text-right">Aksi</Table.Head>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {paginatedPayloads.map((p) => {
                const isCopied = copiedId === p.idempotency_key;
                return (
                  <Table.Row key={p.idempotency_key} className="font-mono text-xs hover:bg-kumo-recessed/40 transition-colors cursor-pointer" onClick={() => setSelectedPayload(p)}>
                    <Table.Cell className="text-kumo-subtle text-[11px] whitespace-nowrap">
                      {p.timestamp.replace('T', ' ').substring(0, 19)}
                    </Table.Cell>
                    <Table.Cell className="font-semibold text-kumo-strong">
                      <div>#{p.meta_id}</div>
                      <div className="break-all text-[10px] text-kumo-subtle font-normal">{p.idempotency_key}</div>
                    </Table.Cell>
                    <Table.Cell>
                      <Badge variant="error">
                        {decisionLabel(p.decision)?.label ?? p.decision}
                      </Badge>
                    </Table.Cell>
                    <Table.Cell className="text-[11px]">
                      <div className="break-words font-medium text-kumo-strong">{p.rule_group_primary}</div>
                      <div className="text-kumo-subtle text-[10px]">{p.agent_name} ({p.agent_id})</div>
                    </Table.Cell>
                    <Table.Cell className="text-[11px]">
                      <span className="text-rose-500 font-bold">{p.anomaly_score.toFixed(4)}</span>
                      <span className="text-kumo-subtle"> &gt; {p.threshold.toFixed(4)}</span>
                    </Table.Cell>
                    <Table.Cell className="text-[11px] text-kumo-subtle max-w-sm truncate" title={p.message}>
                      {p.message}
                    </Table.Cell>
                    <Table.Cell className="text-right">
                      <button
                        type="button"
                        onClick={(event) => { event.stopPropagation(); handleCopy(p.idempotency_key, p.message); }}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded text-[11px] font-mono border border-kumo-hairline bg-kumo-canvas text-kumo-subtle hover:text-kumo-strong hover:bg-kumo-recessed transition-colors cursor-pointer"
                        title="Salin pesan Telegram"
                      >
                        {isCopied ? <Check size={12} className="text-emerald-500" /> : <Copy size={12} />}
                        <span>{isCopied ? 'Tersalin' : 'Salin'}</span>
                      </button>
                    </Table.Cell>
                  </Table.Row>
                );
              })}
            </Table.Body>
          </Table>

          {payloads.length > PAGE_SIZE && (
            <div className="px-6 py-4 border-t border-kumo-hairline bg-kumo-recessed/20">
              <Pagination
                page={page}
                setPage={setPage}
                perPage={PAGE_SIZE}
                totalCount={payloads.length}
              >
                <Pagination.Info />
                <Pagination.Separator />
                <Pagination.Controls />
              </Pagination>
            </div>
          )}
        </div>
      ) : (
        <div className="py-8 text-center text-xs text-kumo-subtle font-mono">
          Belum ada pesan 'perlu dicek segera' pada sesi replay ini.
        </div>
      )}
      <DialogRoot open={Boolean(selectedPayload)} onOpenChange={(open) => { if (!open) setSelectedPayload(null); }}>
        <Dialog className="w-full max-w-2xl rounded-xl border border-kumo-hairline bg-kumo-canvas p-6 shadow-2xl">
          <div className="flex items-start justify-between gap-4 border-b border-kumo-hairline pb-4">
            <div className="space-y-1">
              <DialogTitle>Isi pesan Telegram</DialogTitle>
              <DialogDescription className="text-sm text-kumo-subtle">
                Pratinjau yang akan terlihat di Telegram. Pesan ini memakai format HTML Telegram, bukan Markdown.
              </DialogDescription>
            </div>
            <DialogClose onClick={() => setSelectedPayload(null)}>Tutup</DialogClose>
          </div>
          {selectedPayload && (
            <div className="mt-5 space-y-3">
              <div className="flex items-center justify-between gap-3">
                <p className="text-xs font-semibold uppercase tracking-wider text-kumo-subtle">Pratinjau pesan</p>
                <Badge variant="secondary">HTML Telegram</Badge>
              </div>
              <div className="rounded-lg border border-kumo-hairline bg-kumo-recessed/40 px-5 py-4">
                <TelegramMessagePreview message={selectedPayload.message} />
              </div>
            </div>
          )}
        </Dialog>
      </DialogRoot>
    </div>
  );
}
