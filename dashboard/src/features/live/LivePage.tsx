import { PageHeader } from '@/components/shared/PageHeader';
import { LiveTriageSummaryCard } from './LiveTriageSummary';
import { LiveTransportDetails } from './LiveTransportDetails';
import { ActiveBucketsTimelineCard } from './ActiveBucketsTimeline';

export function LivePage() {
  return (
    <>
      <PageHeader
        breadcrumbs={['Operasi', 'Pemantauan live']}
        title="Pemantauan live Wazuh"
        description="Beban analyst lebih dulu: pengurangan alert, antrean yang perlu dicek, sebaran level, dan kesegaran data. Detail teknis koneksi ada di bawah"
      />
      <div className="px-6 py-8 lg:px-10 space-y-8">
        <LiveTriageSummaryCard />
        <ActiveBucketsTimelineCard />
        <LiveTransportDetails />
      </div>
    </>
  );
}
