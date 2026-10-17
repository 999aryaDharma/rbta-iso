import { Badge } from '@cloudflare/kumo/components/badge';
import { actionLabel, decisionLabel } from '@/lib/labels';

interface DecisionBadgeProps {
  decision?: string;
  action: string;
}

/** Label Indonesia sebagai teks utama; kode asli (dipakai di skripsi) kecil di sampingnya. */
export function DecisionBadge({ decision, action }: DecisionBadgeProps) {
  const actionCode = action || 'SUPPRESS';
  const actionVariant = actionCode === 'ESCALATE' ? 'error' : actionCode === 'DAILY_DIGEST' ? 'info' : 'secondary';
  const decisionInfo = decisionLabel(decision);
  const actionInfo = actionLabel(actionCode);
  const decisionText = decisionInfo?.label ?? decision;
  const actionText = actionInfo?.label ?? actionCode;
  return (
    <span
      className="inline-flex flex-wrap items-center gap-1"
      aria-label={`Level ${decisionText || 'tidak diketahui'}, aksi ${actionText}`}
    >
      {decision && (
        <span title={decisionInfo?.hint}>
          <Badge variant="secondary" className="text-[11px] font-medium">
            Level: {decisionText}
            {decisionInfo && <span className="ml-1 font-mono text-[9px] opacity-60">{decision}</span>}
          </Badge>
        </span>
      )}
      <span title={actionInfo?.hint}>
        <Badge variant={actionVariant} className="text-[11px] font-semibold">
          Aksi: {actionText}
          {actionInfo && <span className="ml-1 font-mono text-[9px] opacity-60">{actionCode}</span>}
        </Badge>
      </span>
    </span>
  );
}
