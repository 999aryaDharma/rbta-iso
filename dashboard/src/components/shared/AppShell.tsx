import { type ReactNode } from 'react';
import { SidebarProvider } from '@cloudflare/kumo/components/sidebar';
import { AppSidebar } from './Sidebar';
import { Topbar } from './Topbar';

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <SidebarProvider defaultOpen collapsible="icon" peekable>
      <div className="h-screen w-full flex bg-kumo-canvas text-kumo-default antialiased overflow-hidden">
        <AppSidebar />

        <div className="flex-1 flex flex-col min-w-0 h-full overflow-hidden">
          <Topbar />
          <main className="flex-1 overflow-y-auto bg-kumo-base/20 min-w-0">
            {children}
          </main>
        </div>
      </div>
    </SidebarProvider>
  );
}
