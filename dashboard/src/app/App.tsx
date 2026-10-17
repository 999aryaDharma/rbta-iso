import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { lazy, Suspense } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AppShell } from '@/components/shared/AppShell';
import { AuthGate } from '@/components/shared/AuthGate';

import { ThemeProvider } from '@/context/ThemeContext';

const OverviewPage = lazy(() => import('@/features/overview/OverviewPage').then(m => ({ default: m.OverviewPage })));
const RBTAPage = lazy(() => import('@/features/rbta/RBTAPage').then(m => ({ default: m.RBTAPage })));
const MetaAlertsPage = lazy(() => import('@/features/meta-alerts/MetaAlertsPage').then(m => ({ default: m.MetaAlertsPage })));
const MetaAlertDetailPage = lazy(() => import('@/features/meta-alerts/MetaAlertDetailPage').then(m => ({ default: m.MetaAlertDetailPage })));
const RawAlertsPage = lazy(() => import('@/features/raw-alerts/RawAlertsPage').then(m => ({ default: m.RawAlertsPage })));
const RawAlertDetailPage = lazy(() => import('@/features/raw-alerts/RawAlertDetailPage').then(m => ({ default: m.RawAlertDetailPage })));
const ReplayPage = lazy(() => import('@/features/replay/ReplayPage').then(m => ({ default: m.ReplayPage })));
const LivePage = lazy(() => import('@/features/live/LivePage').then(m => ({ default: m.LivePage })));
const BucketDetailPage = lazy(() => import('@/features/live/BucketDetailPage').then(m => ({ default: m.BucketDetailPage })));
const ReviewQueuePage = lazy(() => import('@/features/review/ReviewQueuePage').then(m => ({ default: m.ReviewQueuePage })));
const IntegrationsPage = lazy(() => import('@/features/integrations/IntegrationsPage').then(m => ({ default: m.IntegrationsPage })));
const SystemPage = lazy(() => import('@/features/system/SystemPage').then(m => ({ default: m.SystemPage })));

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 2000,
    },
  },
});

export function App() {
  return (
    <ThemeProvider>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter basename="/dashboard">
          <AuthGate>
            <AppShell>
            <Suspense fallback={<div className="p-10 text-sm text-kumo-subtle">Memuat halaman…</div>}><Routes>
              <Route path="/" element={<Navigate to="/overview" replace />} />
              <Route path="/overview" element={<OverviewPage />} />
              <Route path="/rbta" element={<RBTAPage />} />
              <Route path="/meta-alerts" element={<MetaAlertsPage />} />
              <Route path="/meta-alerts/:metaId" element={<MetaAlertDetailPage />} />
              <Route path="/meta-alerts/:metaId/raw-alerts" element={<RawAlertsPage />} />
              <Route path="/meta-alerts/:metaId/raw-alerts/:alertId" element={<RawAlertDetailPage />} />
              <Route path="/demo" element={<ReplayPage />} />
              <Route path="/replay" element={<Navigate to="/demo" replace />} />
              <Route path="/live" element={<LivePage />} />
              <Route path="/live/buckets/:agentId/:ruleGroup" element={<BucketDetailPage />} />
              <Route path="/live/buckets/:agentId/:ruleGroup/raw-alerts/:alertId" element={<RawAlertDetailPage />} />
              <Route path="/review-queue" element={<ReviewQueuePage />} />
              <Route path="/integrations" element={<IntegrationsPage />} />
              <Route path="/system" element={<SystemPage />} />
            </Routes></Suspense>
          </AppShell>
        </AuthGate>
      </BrowserRouter>
    </QueryClientProvider>
  </ThemeProvider>
  );
}
