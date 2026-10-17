import { LiveStatusCard } from './LiveStatusPanel';

/**
 * Metrik koneksi live (pemrosesan, antrean tunggu, TLS, versi model)
 * sebagai blok sekunder collapsible di bawah timeline. Analis melihat
 * beban kerja dulu; detail teknis hanya dibuka bila diperlukan.
 */
export function LiveTransportDetails() {
  return (
    <details className="rounded-xl border border-kumo-hairline bg-kumo-canvas shadow-xs">
      <summary className="cursor-pointer list-none p-6 text-xs font-semibold uppercase tracking-wider text-kumo-strong hover:text-kumo-default focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-kumo-brand rounded-xl">
        Detail teknis koneksi (opsional)
        <span className="block mt-1 text-[11px] font-normal normal-case tracking-normal text-kumo-subtle">
          Status pemrosesan, antrean tunggu, TLS, dan versi model (bukan beban analyst).
        </span>
      </summary>
      <div className="px-6 pb-6">
        <LiveStatusCard />
      </div>
    </details>
  );
}
