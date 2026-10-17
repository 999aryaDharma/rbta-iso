// Kamus label UI. Satu sumber kebenaran untuk teks yang tampil ke pengguna.
// `label` = teks utama; `hint` = tooltip/penjelasan singkat; `code` = istilah teknis asli.

export const DECISION_LABELS = {
  CRITICAL:           { label: 'Kritis',                       hint: 'Skor melewati batas dan tingkat keparahan ≥ 7.' },
  SUSPICIOUS:         { label: 'Mencurigakan',                 hint: 'Skor melewati batas walau tingkat keparahan rendah.' },
  NOISE_HIGH:         { label: 'Keparahan tinggi, pola biasa', hint: 'Keparahan ≥ 7 tapi polanya mirip data normal.' },
  NOISE:              { label: 'Biasa',                        hint: 'Skor di bawah batas dan keparahan rendah.' },
  CONTEXTUAL_ANOMALY: { label: 'Anomali ringan (diabaikan)',   hint: 'Skor tinggi tapi kecil, keparahan rendah, tanpa MITRE.' },
} as const;

export const ACTION_LABELS = {
  ESCALATE:     { label: 'Perlu dicek segera',          hint: 'Dikirim ke Telegram dan masuk antrean utama.' },
  DAILY_DIGEST: { label: 'Ringkasan harian',            hint: 'Ditinjau berkala, tidak dikirim satu per satu.' },
  SUPPRESS:     { label: 'Tidak ditampilkan di antrean', hint: 'Tetap tersimpan dan bisa ditelusuri.' },
} as const;

export const FEATURE_LABELS = {
  max_severity:                  { label: 'Tingkat keparahan tertinggi', hint: 'Level rule Wazuh tertinggi di kelompok (1–15).' },
  mitre_tactic_count:            { label: 'Jumlah taktik MITRE',         hint: 'Banyaknya taktik MITRE ATT&CK berbeda.' },
  critical_mitre_tactic_present: { label: 'Ada taktik MITRE kritis',     hint: 'Ada Exfiltration, Privilege Escalation, atau Impact.' },
  alert_count_log:               { label: 'Jumlah alert (skala log)',    hint: 'ln(1 + jumlah alert) agar lonjakan tidak mendominasi.' },
  rule_diversity_shannon:        { label: 'Keragaman aturan',            hint: 'Seberapa beragam rule yang muncul (entropi Shannon).' },
  severity_dispersion:           { label: 'Sebaran tingkat keparahan',   hint: 'Seberapa bervariasi level alert di kelompok.' },
  agent_criticality:             { label: 'Tingkat kepentingan aset',    hint: 'Nilai 1–4 dari inventaris aset.' },
} as const;

export const TERMS = {
  metaAlert:      'meta-alert',
  bucketOpen:     'Kelompok alert yang masih terbuka',
  bucketMembers:  'Alert dalam kelompok ini',
  rawIn:          'Alert masuk',
  processingRate: 'Kecepatan pemrosesan alert',
  workerUp:       'Pemrosesan berjalan',
  workerDown:     'Pemrosesan berhenti',
  cycleLag:       'Terakhir cek data',
  eventLag:       'Keterlambatan data',
  stale:          'Data belum diperbarui lebih dari 2 menit',
  consecutiveFail:'Gagal berturut-turut',
  quarantine:     'Alert gagal diproses',
  buffer:         'Antrean tunggu',
  throughput:     'Kecepatan (alert/detik)',
  triageUnits:    'Jumlah yang perlu dicek analyst',
  anomalyScore:   'Skor keanehan',
  rawScore:       'Skor mentah model',
  threshold:      'Batas skor',
  aboveThreshold: 'Melewati batas skor',
  margin:         'Selisih dari batas',
  frozenModel:    'Model tetap (tidak dilatih ulang)',
  modelVersion:   'Versi model',
  deferred:       'Belum aktif',
  evidence:       'Bukti asli',
  warmup:         'Masa belajar awal (100 alert pertama)',
  emaGap:         'Rata-rata jeda antar-alert (terkini)',
  baselineGap:    'Rata-rata jeda antar-alert (awal)',
  baseDeltaT:     'Jendela waktu dasar',
  currentDeltaT:  'Jendela waktu saat ini',
  aggregationKey: 'Dikelompokkan berdasarkan: agen + kategori aturan',
  contamination:  'Alert dari agen/kategori berbeda yang tercampur',
} as const;

export const TERM_HINTS = {
  ARR:        'Alert Reduction Rate: persentase pengurangan alert yang harus dicek. Bukan akurasi.',
  MITRE:      'Kerangka taktik serangan MITRE ATT&CK.',
  RBTA:       'Rule-Based Temporal Aggregation: pengelompokan alert per agen dan kategori dalam jendela waktu adaptif.',
  IF:         'Isolation Forest: model yang memberi skor seberapa tidak biasa sebuah meta-alert.',
  Silhouette: 'Ukuran pemisahan kelompok prioritas. Bukan akurasi deteksi serangan.',
} as const;

type LabelEntry = { label: string; hint: string };

/** Ambil entri kamus; undefined bila kode tidak dikenal (pemanggil jatuh ke kode mentah). */
export function lookupLabel(dict: Readonly<Record<string, LabelEntry>>, code: string | undefined | null): LabelEntry | undefined {
  return code ? dict[code] : undefined;
}

export const decisionLabel = (code?: string | null) => lookupLabel(DECISION_LABELS, code);
export const actionLabel = (code?: string | null) => lookupLabel(ACTION_LABELS, code);
export const featureLabel = (code?: string | null) => lookupLabel(FEATURE_LABELS, code);
