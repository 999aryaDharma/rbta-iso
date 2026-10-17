import { Info } from '@phosphor-icons/react';

interface HintProps {
  /** Penjelasan singkat; juga dipakai sebagai aria-label. */
  text: string;
}

/** Ikon info kecil dengan penjelasan lewat `title` (tooltip bawaan browser). */
export function Hint({ text }: HintProps) {
  return (
    <span
      role="img"
      title={text}
      aria-label={text}
      tabIndex={0}
      className="inline-flex align-middle ml-1 text-kumo-subtle cursor-help"
    >
      <Info size={12} aria-hidden="true" />
    </span>
  );
}
