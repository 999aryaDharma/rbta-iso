import { type ReactNode, useContext, useEffect } from 'react';
import { BreadcrumbContext, type Crumb } from './BreadcrumbContext';

export function PageHeader({
  title,
  description,
  actions,
  breadcrumbs,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
  breadcrumbs?: Crumb[];
}) {
  const { setCrumbs } = useContext(BreadcrumbContext);
  const crumbs: Crumb[] = breadcrumbs && breadcrumbs.length > 0 ? breadcrumbs : ['Analisis', title];
  const crumbKey = JSON.stringify(crumbs);

  useEffect(() => {
    setCrumbs(JSON.parse(crumbKey));
    return () => setCrumbs([]);
  }, [crumbKey, setCrumbs]);

  return (
    <div className="border-b border-kumo-hairline bg-kumo-canvas">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 px-6 py-6 lg:px-10">
        <div className="space-y-2">
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
