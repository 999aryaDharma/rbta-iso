import { createContext } from 'react';

// String polos = label grup tanpa halaman; objek = crumb yang bisa diklik.
export type Crumb = string | { label: string; href: string };

// PageHeader mengisi breadcrumbs halaman aktif, Topbar yang menampilkannya.
export const BreadcrumbContext = createContext<{
  crumbs: Crumb[];
  setCrumbs: (crumbs: Crumb[]) => void;
}>({ crumbs: [], setCrumbs: () => {} });
