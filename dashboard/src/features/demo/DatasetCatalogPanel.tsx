import { Button } from "@cloudflare/kumo/components/button";
import { ArrowClockwise } from "@phosphor-icons/react";
import type { DatasetCatalogStatus } from "@/api/schemas";

export function DatasetCatalogPanel({
  status,
  onRefresh,
  disabled,
}: {
  status?: DatasetCatalogStatus;
  onRefresh: () => void;
  disabled: boolean;
}) {
  const running = status?.status === "STARTING" || status?.status === "RUNNING";
  const total = status?.total_files ?? 0;
  const completed = status?.completed_files ?? 0;
  const percent = total > 0 ? Math.min(100, (completed / total) * 100) : 0;
  const ready =
    status?.status === "COMPLETED" &&
    status.pending_files === 0 &&
    status.failed_files === 0 &&
    status.invalid_files === 0;

  return (
    <section
      aria-labelledby="catalog-title"
      className="rounded-xl border border-kumo-hairline bg-kumo-canvas p-5 shadow-xs"
    >
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex max-w-3xl gap-3">
          <div>
            <h2 id="catalog-title" className="font-bold text-kumo-strong">
              Indeks data replay
            </h2>
            <p className="mt-1 text-sm leading-relaxed text-kumo-subtle">
              Indeks menghitung jumlah alert, rentang waktu, validitas, dan SHA-256 di
              latar belakang sebelum replay seluruh data. File <code>.meta</code>{" "}
              tidak dibaca sebagai alert; hanya <code>.jsonl</code> dan{" "}
              <code>.jsonl.gz</code>.
            </p>
          </div>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={onRefresh}
          disabled={disabled || running}
        >
          <ArrowClockwise
            size={14}
            className={running ? "mr-1 animate-spin" : "mr-1"}
          />{" "}
          Indeks ulang
        </Button>
      </div>

      <div className="mt-4 grid gap-3 sm:grid-cols-[1fr_auto] sm:items-center">
        <div>
          <div className="mb-2 flex justify-between gap-4 text-xs">
            <span className="font-semibold text-kumo-default">
              {ready
                ? `${total} dataset siap`
                : `${completed} dari ${total} dataset diperiksa`}
            </span>
            <span className="font-mono text-kumo-subtle">
              {percent.toFixed(0)}%
            </span>
          </div>
          <div className="h-2 overflow-hidden rounded-full bg-kumo-recessed">
            <div
              className={`h-full rounded-full transition-all ${status?.status === "ERROR" ? "bg-red-500" : ready ? "bg-emerald-500" : "bg-blue-500"}`}
              style={{ width: `${percent}%` }}
            />
          </div>
        </div>
        <span
          className={`rounded-full px-3 py-1 text-xs font-semibold ${ready ? "bg-emerald-500/10 text-emerald-700" : running ? "bg-blue-500/10 text-blue-700" : "bg-amber-500/10 text-amber-700"}`}
        >
          {ready
            ? "Siap untuk Semua dataset"
            : running
              ? "Sedang mengindeks"
              : `${status?.pending_files ?? total} menunggu`}
        </span>
      </div>
      {running && status?.current_file && (
        <p className="mt-2 truncate font-mono text-xs text-kumo-subtle">
          Memeriksa: {status.current_file}
        </p>
      )}
      {status?.last_error && (
        <p className="mt-2 text-xs text-red-600">
          Indeks menemukan masalah. Periksa berkas sebelum menjalankan seluruh
          data.
        </p>
      )}
      {Boolean(status?.invalid_files) && (
        <p className="mt-2 text-xs text-red-600">
          {status?.invalid_files} dataset berisi alert tidak valid. Replay
          seluruh data diblokir sampai diperbaiki.
        </p>
      )}
    </section>
  );
}
