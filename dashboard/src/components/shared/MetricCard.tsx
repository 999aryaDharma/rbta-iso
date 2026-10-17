import { type ReactNode } from 'react';
import { Hint } from './Hint';

interface MetricCardProps {
  label: string;
  value: string | number;
  sub?: string;
  /** Penjelasan singkat (tooltip) di samping label. */
  hint?: string;
  icon?: ReactNode;
}

export function MetricCard({ label, value, sub, hint, icon }: MetricCardProps) {
  return (
    <div className="p-6 rounded-xl border border-kumo-hairline bg-kumo-canvas hover:border-kumo-line transition-all shadow-xs flex flex-col justify-between space-y-2">
      <div className="flex items-center justify-between text-xs font-semibold text-kumo-subtle uppercase tracking-wider">
        <span className="truncate">{label}{hint && <Hint text={hint} />}</span>
        {icon && <span className="text-kumo-subtle shrink-0 ml-2">{icon}</span>}
      </div>
      <div className="text-3xl lg:text-4xl font-bold font-mono text-kumo-strong tracking-tight">
        {value}
      </div>
      {sub ? (
        <div className="text-xs lg:text-sm text-kumo-subtle truncate">
          {sub}
        </div>
      ) : (
        <div className="h-4" />
      )}
    </div>
  );
}
