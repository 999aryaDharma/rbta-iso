# Runbook Demo Sidang RBTA–Isolation Forest

## Tujuan dan batas klaim

Demo membuktikan alur teknis yang dapat direproduksi: alert Wazuh historis dinormalisasi, dikelompokkan oleh RBTA, diberi skor oleh model beku, diprioritaskan, dan ditelusuri kembali ke evidence mentah. Demo tidak membuktikan kebenaran serangan, akurasi serangan, atau integrasi eksternal live.

## Sebelum masuk ruang sidang

1. Bekukan exact commit, model version, dataset, dan SHA-256 dataset pada catatan sidang.
2. Gunakan dataset berklasifikasi `golden` sebanyak 5.000–20.000 alert; jangan memakai arsip 2,5 GB.
3. Jalankan seluruh test dan build, lalu simpan outputnya.
4. Buka `http://HOST:8010/dashboard/demo` dan pastikan health API hijau.
5. Siapkan video dan tangkapan layar hasil run yang sama sebagai cadangan.
6. Pastikan Wazuh live, Shuffle, dan Telegram eksternal disebut `deferred`, bukan aktif.

Dataset golden dapat dibangun dari arsip nyata tanpa membuat serangan sintetis:

```bash
python scripts/build_golden_demo_dataset.py SOURCE.jsonl.gz data/replay/golden-sidang.jsonl.gz --size 10000 --seed 42
```

## Alur presentasi 7 menit

| Waktu | Tindakan | Narasi aman |
|---|---|---|
| 0:00–0:45 | Tunjukkan kartu batas riset | “Alert, anomali, dan serangan adalah tiga konsep berbeda.” |
| 0:45–1:30 | Pilih golden dataset dan tunjukkan hash/model | “Input dan model dibekukan agar hasil dapat direproduksi.” |
| 1:30–3:00 | Mulai Demo pada MAX | “ARR sementara adalah pengurangan unit triase, bukan akurasi.” |
| 3:00–4:00 | Jelaskan pipeline dan skor | “Isolation Forest hanya memberi prioritas keanehan; Tukey dan decision matrix menentukan eskalasi.” |
| 4:00–4:45 | Drill-down meta-alert ke raw evidence | “Tidak ada konteks sumber yang dibuang.” |
| 4:45–6:15 | Jalankan/tampilkan evaluasi lengkap | “Time-only dibanding contextual-fixed dan contextual-adaptive; context purity mencegah ARR tinggi yang menyesatkan.” |
| 6:15–7:00 | Tampilkan artifact JSON dan batasan | “Silhouette adalah validitas struktural internal, bukan akurasi deteksi serangan.” |

## Go/no-go

Demo dinyatakan go hanya jika branch adalah `prod/final-dashboard-demo`, exact SHA dicatat, dataset valid, SHA tampil, model tersedia, API sehat, golden replay pernah selesai, dan fallback tersedia. Jika salah satu tidak terpenuhi, gunakan rekaman hasil terverifikasi dan jelaskan kendalanya.

## Pertanyaan yang harus siap dijawab

- Mengapa baseline time-only bisa mempunyai ARR lebih tinggi? Karena ia dapat mencampur konteks yang tidak berkaitan; karena itu ARR selalu dibaca bersama context purity.
- Mengapa tidak melaporkan FPR/accuracy? Tidak ada ground truth serangan yang sah pada dataset utama.
- Apa fungsi `contamination="auto"`? Konfigurasi offset internal scikit-learn, bukan estimator prevalensi serangan dan bukan penentu eskalasi sistem ini.
- Apakah model dilatih ulang saat demo? Tidak. Replay memakai artifact model beku dan hanya melakukan inference.
- Mengapa skor bisa di luar 0–1? Kalibrasi referensi dipertahankan tanpa clipping agar perubahan distribusi terlihat dan dapat diaudit.
