import { type ReactNode } from 'react';

export function PageHeader({
  title,
  description,
  actions,
  breadcrumbs,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
  breadcrumbs?: string[];
}) {
  return (
    <div className="border-b border-kumo-hairline bg-kumo-canvas">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 px-6 py-6 lg:px-10">
        <div className="space-y-2">
          {breadcrumbs && breadcrumbs.length > 0 ? (
            <div className="text-xs font-semibold text-kumo-subtle flex items-center gap-1.5 uppercase tracking-wider mb-1">
              {breadcrumbs.map((crumb, idx) => (
                <span key={crumb} className="flex items-center gap-1.5">
                  {idx > 0 && <span className="text-kumo-hairline">/</span>}
                  <span className={idx === breadcrumbs.length - 1 ? 'text-kumo-strong font-semibold' : ''}>
                    {crumb}
                  </span>
                </span>
              ))}
            </div>
          ) : (
            <div className="text-xs font-semibold text-kumo-subtle uppercase tracking-wider mb-1 flex items-center gap-1.5">
              <span>Analisis</span>
              <span className="text-kumo-hairline">/</span>
              <span className="text-kumo-strong font-semibold">{title}</span>
            </div>
          )}
          <h1 className="text-2xl lg:text-3xl font-bold tracking-tight text-kumo-strong">
            {title}
          </h1>
          {description && (
            <p className="text-sm lg:text-base text-kumo-subtle max-w-3xl leading-relaxed">
              {description}
            </p>
          )}
        </div>
        {actions && <div className="flex items-center gap-3 shrink-0">{actions}</div>}
      </div>
    </div>
  );
}
