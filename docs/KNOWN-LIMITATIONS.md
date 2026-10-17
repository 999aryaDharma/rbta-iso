# Batas yang diketahui

Dokumen ini mencatat batas implementasi yang **sengaja belum diperbaiki** karena menyentuh
algoritma inti yang dikunci untuk skripsi. Perbaikan direncanakan setelah sidang dan wajib
disertai analisis dampak metode.

## 1. State temporal terminal-invalid bila jumlah jeda warmup = 0

**Lokasi:** `src/rbta/temporal_state.py`, `AgentTemporalState.observe()` (mode adaptif).

**Perilaku saat ini.** Selama warmup (event ke-2 sampai ke-100 per agen) hanya kedatangan maju
yang menyumbang jeda. Pada event ke-100, bila `warmup_gaps` kosong atau `sum(warmup_gaps) <= 0`,
state ditandai `_is_terminal_invalid = True` dan `TemporalStateError` dilempar. Ini terjadi bila
ke-100 event pertama sebuah agen memiliki timestamp identik (mis. impor batch dengan detik yang
sama) atau datang mundur seluruhnya.

**Dampak di live.** `engine.process` transaksional: snapshot state kandidat yang gagal tidak
di-commit, sehingga state yang tersimpan tetap di event ke-99. Setiap alert berikutnya dari agen
itu kembali mencapai event ke-100 dan gagal lagi. `TemporalStateError` termasuk error karantina di
`LiveIngestionCoordinator`, jadi alert-alert tersebut dikarantina satu per satu. Bila jumlahnya
melewati breaker (1% kandidat per siklus atau 100), siklus live berhenti dengan latch
`breaker_tripped` sampai operator mengonfirmasi. Tidak ada alert yang diam-diam terbuang (semua
tercatat di `quarantined_alerts`), tetapi agen itu tidak pernah teragregasi.

**Mengapa belum diperbaiki.** Perubahan apa pun mengubah cara Elastic Time Window dibentuk,
padahal hasil Bab IV berasal dari commit `16ab574` dengan perilaku ini. Pada korpus skripsi
kasus ini tidak terjadi (tidak ada `TemporalStateError` di run).

**Usulan solusi (setelah sidang).**

1. Jangan jadikan terminal: bila `sum(warmup_gaps) <= 0` pada event ke-100, perpanjang warmup
   sampai ada minimal satu jeda positif (tetap memakai `base_delta_t` selama warmup). Baseline
   kemudian = rata-rata jeda yang terkumpul. Ini tidak pernah membuang alert dan tidak mengubah
   agen yang sudah normal.
2. Alternatif lebih sederhana: baseline jatuh ke `base_delta_t` (rasio EMA = 1) bila jumlah jeda 0,
   dengan flag `baseline_fallback=True` di snapshot agar terlihat di dashboard dan bukti.
3. Wajib: tes regresi bahwa output fixture T3 (`tests/fixtures/parity_scores_golden.json`) dan
   replay korpus skripsi tidak berubah, plus tes kasus 100 timestamp identik; catat perubahan
   metode di naskah.

## 2. Lainnya (operasional)

- Cooldown eskalasi (T10) disimpan in-memory: restart mereset cooldown dan ringkasan "+N" yang
  belum terkirim hilang (item yang ditekan tetap tercatat di `suppressed_notifications`).
- Retensi (T12): alert dengan event time lebih tua dari `RBTA_RETENTION_DAYS` tidak di-ingest live
  (dihitung sebagai `retention_expired`) agar ID yang dipangkas tidak diproses ulang.
- `top_deviations` (T11) adalah (x − median reference) / IQR reference, tetapi sklearn memakai
  skala 1 bila IQR = 0 (empat fitur di partisi reference). Ini penjelasan deskriptif, bukan
  atribusi skor Isolation Forest.
