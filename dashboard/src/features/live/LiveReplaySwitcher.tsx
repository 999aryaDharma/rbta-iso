import { useState } from "react";
import { Pulse, Play } from "@phosphor-icons/react";

export type LiveContext = "live" | "replay";
export type SwitcherStatus = "idle" | "loading" | "error" | "empty";

interface LiveReplaySwitcherProps {
  mode: LiveContext;
  onChange: (mode: LiveContext) => void;
  status?: SwitcherStatus;
  errorMessage?: string;
  disabled?: boolean;
}

const STATUS_LABEL: Record<Exclude<SwitcherStatus, "idle">, string> = {
  loading: "Memuat konteks…",
  error: "Gagal memuat konteks",
  empty: "Belum ada meta-alert pada konteks ini",
};

const CONTEXT_META = {
  live: {
    label: "Live",
    caption: "Menampilkan: Live (data langsung).",
    Icon: Pulse,
  },
  replay: {
    label: "Replay",
    caption: "Menampilkan: Replay (data historis).",
    Icon: Play,
  },
} as const;

export function LiveReplaySwitcher({
  mode,
  onChange,
  status = "idle",
  errorMessage,
  disabled = false,
}: LiveReplaySwitcherProps) {
  const [pending, setPending] = useState<LiveContext | null>(null);
  const busy = status === "loading" || pending !== null;

  const select = (next: LiveContext) => {
    if (next === mode || disabled || busy) return;
    setPending(next);
    try {
      onChange(next);
    } finally {
      setPending(null);
    }
  };

  return (
    <div className="p-4 rounded-xl border border-kumo-hairline bg-kumo-canvas shadow-xs space-y-3">
      <div
        role="radiogroup"
        aria-label="Konteks data: live atau replay"
        className="flex gap-2"
      >
        {(["live", "replay"] as const).map((value) => {
          const active = mode === value;
          const { label, Icon } = CONTEXT_META[value];
          return (
            <button
              key={value}
              type="button"
              role="radio"
              aria-checked={active}
              aria-pressed={active}
              disabled={disabled || busy}
              onClick={() => select(value)}
              data-active={active}
              className={
                active
                  ? "switcher-active inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-bold border border-transparent bg-kumo-brand text-white shadow-xs cursor-default"
                  : "inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold border border-kumo-hairline bg-transparent text-kumo-subtle hover:text-kumo-strong hover:border-kumo-strong/40"
              }
            >
              <Icon size={15} weight={active ? "fill" : "regular"} aria-hidden="true" />
              {label}
            </button>
          );
        })}
      </div>

      {status === "loading" && (
        <p role="status" className="text-xs text-kumo-subtle">
          {STATUS_LABEL.loading}
        </p>
      )}
      {status === "error" && (
        <p role="alert" className="text-xs text-red-600">
          {STATUS_LABEL.error}
          {errorMessage ? `: ${errorMessage}` : ""}
        </p>
      )}
      {status === "empty" && (
        <p role="status" className="text-xs text-kumo-subtle">
          {STATUS_LABEL.empty}
        </p>
      )}
      {status === "idle" && (
        <p className="text-xs text-kumo-strong font-medium">
          {mode === "live" ? CONTEXT_META.live.caption : CONTEXT_META.replay.caption}{" "}
          <span className="text-kumo-subtle font-normal">
            {mode === "live"
              ? "Sumber data dapat ditelusuri, sama seperti replay."
              : "Pilih Live untuk kembali ke data langsung."}
          </span>
        </p>
      )}
    </div>
  );
}
