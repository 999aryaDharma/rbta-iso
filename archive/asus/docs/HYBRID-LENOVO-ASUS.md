# Menjalankan Demo Hybrid di Lenovo dan ASUS

Panduan ini memakai kode, model, API, dan alur evaluasi yang sama pada dua host. Perbedaannya hanya path host dan kapasitas resource. Dataset tidak disalin ke container dan selalu dipasang read-only.

## Struktur dataset yang didukung

Folder `indexer-export` boleh berisi banyak file harian:

```text
wazuh-alerts-4.x-2026.04.02.jsonl
wazuh-alerts-4.x-2026.04.02.meta
wazuh-alerts-4.x-2026.04.03.jsonl
wazuh-alerts-4.x-2026.04.03.meta
...
```

Hanya `.jsonl` dan `.jsonl.gz` yang dibaca sebagai alert. File `.meta` adalah sidecar hasil ekspor dan sengaja diabaikan. Ikon WinRAR pada Windows Explorer hanya menunjukkan asosiasi aplikasi; ekstensi `.jsonl` tetap diperlakukan sebagai teks JSON Lines.

## A. Lenovo — PowerShell + Docker Desktop

Prasyarat: Git, Python 3.11+, Docker Desktop dengan Linux containers, dan model `reference-v1`.

```powershell
git switch prod/final-dashboard-demo
git pull --ff-only origin prod/final-dashboard-demo
Copy-Item deploy/local/.env.example deploy/local/.env
notepad deploy/local/.env
```

Nilai dataset yang sudah disiapkan di template:

```dotenv
RBTA_REPLAY_HOST_DIR=D:/KAMPUS/SKRIPSI/wazuh-data-2026/indexer-export
```

Gunakan forward slash untuk path Docker Desktop. Simpan model pada:

```text
models/reference-v1/isolation_forest.joblib
models/reference-v1/robust_scaler.joblib
models/reference-v1/score_calibration.json
models/reference-v1/threshold.json
models/reference-v1/feature_schema.json
models/reference-v1/metadata.json
models/reference-v1/manifest.json
```

Nama file persis mengikuti bundle yang dihasilkan `ModelRegistry`; jangan mengganti isi atau version folder secara manual. Jalankan:

```powershell
py scripts/deploy/local.py up
```

Launcher memvalidasi path dan model, membangun container, menunggu `/ready`, lalu mengindeks seluruh file sambil menampilkan progres. Setelah selesai, buka:

```text
http://127.0.0.1:8010/dashboard/demo
```

Perintah operasional:

```powershell
py scripts/deploy/local.py status
py scripts/deploy/local.py logs
py scripts/deploy/local.py index
py scripts/deploy/local.py down
```

State, evidence SQLite, cache indeks, dan run artifact disimpan di Docker volume `rbta-local-state`. Menghapus container tidak menghapus volume. Jangan menjalankan `docker volume rm rbta-local-state` bila evidence masih diperlukan.

## B. Lenovo — WSL2

Pada WSL, ubah hanya path replay pada `deploy/local/.env`:

```dotenv
RBTA_REPLAY_HOST_DIR=/mnt/d/KAMPUS/SKRIPSI/wazuh-data-2026/indexer-export
```

Lalu:

```bash
python3 scripts/deploy/local.py up
```

Docker Desktop harus mengaktifkan WSL integration untuk distribusi tersebut.

## C. ASUS server

ASUS tetap memakai deployment yang ada:

```bash
git switch prod/final-dashboard-demo
git pull --ff-only origin prod/final-dashboard-demo
cp deploy/asus/.env.example deploy/asus/.env
nano deploy/asus/.env
bash scripts/deploy/asus-preflight.sh
bash scripts/deploy/asus-deploy.sh
```

Path default ASUS:

```dotenv
RBTA_STATE_HOST_DIR=/srv/rbta-iso/state
RBTA_MODEL_HOST_DIR=/srv/rbta-iso/models
RBTA_REPLAY_HOST_DIR=/srv/rbta-iso/replay
RBTA_HOST_PORT=8010
```

`.jsonl.gz` kini valid di Lenovo maupun ASUS.

## Menyiapkan model

Pilihan paling aman untuk membandingkan host adalah menyalin exact bundle model yang sudah dilatih dari ASUS ke `models/reference-v1` di Lenovo dan membandingkan checksum. Jangan melatih model baru tepat sebelum sidang.

Jika memang perlu melakukan training resmi pada corpus April–Agustus, jalankan dari environment Python proyek:

```powershell
py -m src.research.orchestrator `
  --input "D:\KAMPUS\SKRIPSI\wazuh-data-2026\indexer-export" `
  --output-dir artifacts/research-runs `
  --model-version reference-v1 `
  --delta-t auto `
  --seed 42
```

Input direktori dibaca secara deterministik dan diurutkan global berdasarkan timestamp. Pipeline menolak ID Wazuh duplikat dan menerapkan split kronologis sebelum agregasi:

| Partisi | Proporsi | Fungsi |
|---|---:|---|
| Reference | 60% awal | fit RobustScaler dan Isolation Forest |
| Calibration | 20% berikut | kalibrasi skor dan threshold Tukey |
| Test | 20% akhir | evaluasi tanpa refit |

Output model berada di `artifacts/research-runs/<run-id>/models/reference-v1`. Bekukan folder itu beserta `run_manifest.json`, `research_summary.json`, Git SHA, dan SHA-256 corpus sebelum digunakan untuk demo.

## Urutan demo yang disarankan

1. Pastikan kartu **Indeks corpus replay** berstatus siap.
2. Pilih satu dataset harian kecil untuk menjelaskan raw → RBTA → tujuh fitur → Isolation Forest → decision matrix.
3. Tunjukkan evidence drill-down dan batas klaim.
4. Jalankan evaluasi lengkap setelah replay selesai.
5. Gunakan **Semua dataset** hanya untuk benchmark yang sudah dijadwalkan, bukan sebagai pembuka demo sidang.

Indeks dataset hanya menghitung provenance dan validitas. Indeks bukan training, bukan evaluasi model, dan tidak mengubah alert. Replay real-time memakai model beku; evaluasi lengkap pasca-replay menghitung sensitivitas Δt, tiga skenario agregasi, robustness noise, runtime, scoring model, dan Silhouette permutation.

## Troubleshooting singkat

- **Model version directory does not exist**: pastikan `RBTA_MODEL_HOST_DIR` menunjuk ke parent folder yang berisi `reference-v1`.
- **Drive D: tidak dapat dimount**: pastikan Docker Desktop berjalan dan memakai Linux containers; gunakan path forward slash.
- **Indeks gagal pada satu file**: lihat nama file pada kartu indeks, validasi baris JSON yang disebut, lalu indeks ulang.
- **Port 8010 dipakai**: pilih port 1024–65535 lain di `.env`, misalnya 8011.
- **Full corpus lambat**: ini normal untuk hashing dan canonicalization pertama. Cache berikutnya memakai ukuran + mtime dan tidak membaca ulang file yang tidak berubah.
