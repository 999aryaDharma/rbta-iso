# Glosarium label dashboard

Satu sumber kebenaran di kode: `dashboard/src/lib/labels.ts`. Dokumen ini memetakan **teks di dashboard**
ke **istilah teknis/kode** dan **istilah yang dipakai di skripsi**, supaya penulisan Bab IV konsisten.

> Sistem ini mengurangi dan memprioritaskan unit triase. Alert bukan otomatis serangan, anomaly score bukan
> label serangan, dan setiap MetaAlert harus tetap dapat ditelusuri ke bukti mentahnya.

Catatan: kolom "Istilah di skripsi" disusun dari draf Bab IV–V yang ada di `docs/thesis/` dan kode sumber; periksa ulang
terhadap naskah final sebelum mengutip.

Aturan penulisan: "meta-alert" (huruf kecil, tanda hubung; "Meta-alert" di awal kalimat). Kode keputusan
(CRITICAL, ESCALATE, dst.) tetap tampil kecil di samping label Indonesia. Nama field API, nilai enum,
query param, dan route **tidak berubah**.

## 1. Level (decision)

| Tampil di dashboard | Kode | Arti | Istilah di skripsi |
| --- | --- | --- | --- |
| Kritis | `CRITICAL` | Skor melewati batas dan tingkat keparahan ≥ 7 | CRITICAL (Decision Matrix) |
| Mencurigakan | `SUSPICIOUS` | Skor melewati batas, tingkat keparahan rendah | SUSPICIOUS |
| Keparahan tinggi, pola biasa | `NOISE_HIGH` | Keparahan ≥ 7, skor di bawah batas | NOISE_HIGH |
| Biasa | `NOISE` | Skor di bawah batas, keparahan rendah | NOISE |
| Anomali ringan (diabaikan) | `CONTEXTUAL_ANOMALY` | Skor tinggi tapi kecil, keparahan rendah, tanpa MITRE (False Positive Gate) | CONTEXTUAL_ANOMALY |

## 2. Aksi (action)

| Tampil di dashboard | Kode | Arti | Istilah di skripsi |
| --- | --- | --- | --- |
| Perlu dicek segera | `ESCALATE` | Dikirim ke Telegram, masuk antrean utama | ESCALATE (eskalasi) |
| Ringkasan harian | `DAILY_DIGEST` | Ditinjau berkala, tidak dikirim satu per satu | DAILY_DIGEST |
| Tidak ditampilkan di antrean | `SUPPRESS` | Tetap tersimpan dan dapat ditelusuri | SUPPRESS |

Level dan aksi adalah dua hal berbeda: level = hasil Decision Matrix, aksi = tindak lanjut triase. Keduanya
bukan bukti serangan.

## 3. Tujuh fitur penilaian

| Tampil di dashboard | Nama fitur (kode) | Istilah di skripsi (Bab III) |
| --- | --- | --- |
| Tingkat keparahan tertinggi | `max_severity` | max_severity |
| Jumlah taktik MITRE | `mitre_tactic_count` | mitre_tactic_count |
| Ada taktik MITRE kritis | `critical_mitre_tactic_present` | critical_mitre_tactic_present |
| Jumlah alert (skala log) | `alert_count_log` | alert_count_log |
| Keragaman aturan | `rule_diversity_shannon` | rule_diversity_shannon (entropi Shannon) |
| Sebaran tingkat keparahan | `severity_dispersion` | severity_dispersion |
| Tingkat kepentingan aset | `agent_criticality` | agent_criticality |

## 4. Istilah umum

| Tampil di dashboard | Istilah teknis / kode | Istilah di skripsi |
| --- | --- | --- |
| meta-alert | `MetaAlert` | MetaAlert (meta-alert) |
| Kelompok alert yang masih terbuka | bucket aktif RBTA | bucket aktif |
| Alert dalam kelompok ini | anggota bucket (`source_alert_ids`) | anggota bucket |
| Alert masuk | raw alert / `raw_alert_count` | raw alert |
| Kecepatan pemrosesan alert | ingestion & aggregation rate | laju ingesti |
| Pemrosesan berjalan / berhenti | `worker_alive` | live worker |
| Terakhir cek data | `lag_sec` (umur siklus) | (tidak dipakai) |
| Keterlambatan data | `event_lag_sec` | keterlambatan event |
| Alert gagal diproses | `quarantine_total` | karantina |
| Antrean tunggu | `buffer_size` (order buffer) | order buffer |
| Jumlah yang perlu dicek analyst | unit triase | unit triase |
| Skor keanehan | `anomaly_score` | skor anomali (anomaly score) |
| Skor mentah model | `raw_model_score` | skor mentah |
| Batas skor | `threshold_used` (Tukey IQR, θ) | ambang Tukey (θ) |
| Melewati batas skor | `anomalies_detected` | di atas ambang |
| Selisih dari batas | `margin` | margin |
| Model tetap (tidak dilatih ulang) | frozen model | model beku |
| Versi model | `model_version` | versi model |
| Belum aktif | `DEFERRED` | deferred |
| Bukti asli | raw evidence | bukti mentah (raw evidence) |
| Masa belajar awal (100 alert pertama) | warmup | warmup |
| Rata-rata jeda antar-alert (terkini / awal) | `ema_gap` / `baseline_gap` | EMA gap / baseline gap |
| Jendela waktu dasar / saat ini | `base_delta_t` / `current_delta_t` | Δt dasar / Δt saat ini |
| Dikelompokkan berdasarkan: agen + kategori aturan | `(agent_id, rule_group_primary)` | kunci bucket RBTA |
| Alert dari agen/kategori berbeda yang tercampur | kontaminasi konteks | kontaminasi |
| Pembanding acak (100 kali) untuk Silhouette | null permutation distribution | distribusi null permutasi |
| Nilai Silhouette model | observed Silhouette | Silhouette teramati |
| Ketahanan terhadap noise | noise robustness | ketahanan noise |
| Noise yang ikut tergabung | noise absorption rate | tingkat penyerapan noise |

Hint (ikon ⓘ) untuk istilah singkat: ARR, MITRE, RBTA, Isolation Forest, Silhouette (lihat `TERM_HINTS`).

## 5. Dihapus dari tampilan

- Metrik **Context purity** (tidak dipakai di skripsi) dihapus dari tabel evaluasi. Endpoint backend tidak
  diubah; field itu hanya diabaikan frontend.

## 6. Teks yang sengaja dipertahankan berbahasa Inggris

| Teks | Alasan |
| --- | --- |
| Isolation Forest, RBTA, Rule Group, Tukey IQR, RobustScaler, Silhouette, MITRE ATT&CK, Wazuh, Telegram, Shuffle, Indexer/API, API key, TLS, JSON, SHA-256, SQLite (WAL), SOC | Nama produk, metode, atau standar; dirujuk persis di skripsi |
| Kode keputusan/aksi kecil (CRITICAL, ESCALATE, ...) dan nama fitur teknis (`max_severity`, ...) | Aturan proyek: tetap terlihat sebagai teks sekunder/tooltip untuk Bab III–IV |
| Badge `Live` dan `Replay` | Nama mode yang sudah dipakai di runbook dan sidang |
| `Level` (kolom/badge) | Istilah di skripsi untuk hasil Decision Matrix |
| Nama dan deskripsi komponen di halaman Integrasi, `claim_boundary` di panel evaluasi, nama fase evaluasi | Teks berasal dari backend (`src/`), di luar cakupan perubahan UI-saja |
| Nilai status mentah di ringkasan replay (`IDLE`, `RUNNING`, ...) | Nilai enum backend ditampilkan apa adanya sebagai nilai metrik |
| Istilah di tooltip bernama variabel (`ln(1 + jumlah alert)`, `(agent_id, rule_group_primary)`) | Rumus/kunci yang sama dengan Bab III |
| Teks di tombol/URL internal (`/dashboard/...`) | Route tidak diubah |
