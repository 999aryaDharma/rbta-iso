# Runbook: menerapkan `fix/prod-hardening` di CT Proxmox

Tujuan: produksi live memakai model dan lingkungan yang sama dengan skripsi
(`rbta-if-thesis-v1`, θ = 0.8724522092452893, scikit-learn 1.7.2, Python 3.11, Δt = 10 menit)
dan mulai mengumpulkan bukti harian untuk Bab IV.

> Sistem ini mengurangi dan memprioritaskan unit triase. Alert bukan otomatis serangan, anomaly
> score bukan label serangan, dan setiap MetaAlert harus tetap dapat ditelusuri ke bukti mentahnya.

Semua perintah `docker compose` dijalankan di `~/rbta/deploy/ct` di dalam CT. Jangan menyalin
isi `.env`, token, atau password ke chat/log/commit.

## 0. Penting: urutan bootstrap CD

CT saat ini menjalankan `auto-update.sh` **lama**, yang men-deploy **setiap** push ke
`prod/final-dashboard-demo`. Gerbang tag `release-*` (T13) baru berlaku setelah skrip baru ikut
ter-pull. Jadi:

1. Siapkan langkah 1–4 di bawah **sebelum** merge ke `prod/final-dashboard-demo`.
2. Merge PR `fix/prod-hardening` → `prod/final-dashboard-demo` (oleh peneliti). Skrip lama akan
   langsung men-deploy commit merge itu (±5 menit).
3. Sejak saat itu hanya commit bertag `release-*` yang di-deploy (bagian 7).

Bila ingin mengontrol penuh, matikan cron sementara (`crontab -e`, beri `#`), lakukan langkah
manual bagian 5, lalu aktifkan lagi.

## 1. Backup state

```bash
cd ~/rbta/deploy/ct
docker run --rm -v rbta-ct-live:/s -v "$PWD":/b alpine tar czf /b/live-backup-$(date +%Y%m%d).tgz -C /s .
docker run --rm -v rbta-ct-archive:/a -v "$PWD":/b alpine tar czf /b/archive-backup-$(date +%Y%m%d).tgz -C /a .
```

## 2. Salin model thesis (dari laptop)

Nama direktori **harus** sama dengan `RBTA_MODEL_VERSION`.

```powershell
# di laptop, dari root repo
scp -r "docs/thesis/hasil-run-20261001/model" root@<ip-ct>:~/rbta/models/rbta-if-thesis-v1
```

Verifikasi di CT:

```bash
sha256sum ~/rbta/models/rbta-if-thesis-v1/isolation_forest.joblib
# harus: 0447550cd531cb88dc5d5ef60ed50fd525e201b154ba999d5fa84f2c3a6432f4
grep -E '"(model_version|sklearn_version)"' ~/rbta/models/rbta-if-thesis-v1/metadata.json
```

## 3. File kekritisan agen (opsional, perubahan metode)

Tanpa file ini dipakai tabel bawaan `src/config/domain.py` (sama dengan skripsi). Mengisi file
mengubah fitur `agent_criticality`: catat keputusan dan sha256-nya di naskah.

```bash
cp ~/rbta/deploy/ct/config/agent_criticality.example.json ~/rbta/deploy/ct/config/agent_criticality.json
nano ~/rbta/deploy/ct/config/agent_criticality.json   # {"nama_atau_id": 1-4}
sha256sum ~/rbta/deploy/ct/config/agent_criticality.json
```

## 4. Perbarui `deploy/ct/.env`

Tambahkan/ubah (lihat komentar di `deploy/ct/.env.example`):

```bash
RBTA_MODEL_VERSION=rbta-if-thesis-v1
RBTA_EXPECTED_MODEL_SHA256=0447550cd531cb88dc5d5ef60ed50fd525e201b154ba999d5fa84f2c3a6432f4
RBTA_BASE_DELTA_T_MIN=10
RBTA_EXCLUDED_AGENTS=agent-test,test-n8n        # cek nama agen uji yang sebenarnya
RBTA_AGENT_CRITICALITY_FILE=/app/config/agent_criticality.json   # kosongkan bila tidak dipakai
RBTA_DASHBOARD_URL=http://<ip-ct>:8010/dashboard
RBTA_EVIDENCE_EXPORT_AT=00:05
RBTA_DIGEST_AT=07:30
RBTA_ESCALATION_COOLDOWN_MIN=60
RBTA_RETENTION_DAYS=90
RBTA_BIND_ADDR=0.0.0.0
```

### 4a. State live: baru (disarankan) atau lanjut

Ganti model + Δt + (opsional) kekritisan pada state lama mencampur dua konfigurasi dalam satu
history dan state temporal per agen. Untuk periode bukti Bab IV yang bersih, **mulai state baru**
(setelah backup bagian 1):

```bash
docker compose down
docker volume rm rbta-ct-live      # arsip (rbta-ct-archive) tetap
```

Bila tetap memakai state lama, worker akan menolak start karena pin model lama. Isi sekali:

```bash
RBTA_LIVE_MODEL_OVERRIDE=rbta-if-thesis-v1
# bila file kekritisan diisi, log worker menyebut hash baru:
RBTA_LIVE_DERIVATION_OVERRIDE=<hash dari pesan error "Live derivation config mismatch">
```

lalu kosongkan lagi setelah start berhasil (override disimpan sebagai pin baru). Catatan: raw
evidence lama menyimpan `agent_criticality` lama; alert yang di-poll ulang dengan kekritisan baru
akan dikarantina sebagai konflik evidence. Itu alasan state baru lebih aman.

## 5. Rebuild dan start (manual)

```bash
cd ~/rbta && git fetch origin && git status   # pastikan di prod/final-dashboard-demo hasil merge
cd deploy/ct
docker compose build                    # image baru: python:3.11-slim + sklearn 1.7.2
docker compose up -d
docker run --rm -v rbta-ct-live:/s -v rbta-ct-archive:/a alpine chown -R 10001:10001 /s /a
docker compose restart rbta-service
sleep 45
```

## 6. Verifikasi

```bash
curl -s http://127.0.0.1:8010/ready
# {"ready":true,"active_model_version":"rbta-if-thesis-v1"}  (tanpa threshold)

curl -s -H "Authorization: Bearer <RBTA_API_KEY>" http://127.0.0.1:8010/api/v1/live/status | python3 -m json.tool
```

Periksa di status:

| Field | Harapan |
| --- | --- |
| `worker_alive`, `consecutive_failures` | `true`, `0` |
| `live_model_version` | `rbta-if-thesis-v1` |
| `model.sha256` / `model.threshold` | `0447550c…32f4` / `0.8724522092452893` |
| `base_delta_t_sec` | `600.0` |
| `excluded_agents`, `excluded_alerts_total` | daftar agen uji, counter naik bila agen itu mengirim alert |
| `agent_criticality_file` | `null` atau `{sha256, entries}` sesuai bagian 3 |
| `disk.state.warning`, `disk.archive.warning` | `false` |
| `dispatcher.cooldown_min` | `60.0` |

```bash
docker compose logs rbta-service | grep -E "Active model sha256|Live RBTA base delta_t|criticality|job started"
docker compose logs rbta-service | grep -i InconsistentVersionWarning   # harus kosong
```

Guard identitas: isi `RBTA_EXPECTED_MODEL_SHA256` yang salah satu karakter lalu
`docker compose up -d` → container harus gagal start dengan `Model identity mismatch`
(kembalikan nilainya setelah uji).

Bukti harian muncul setelah 00:05 WITA (atau saat restart bila jadwal hari itu sudah lewat):

```bash
docker compose exec rbta-service ls /app/data/live/evidence
curl -s -H "Authorization: Bearer <RBTA_API_KEY>" -o daily_summary.csv \
  http://127.0.0.1:8010/api/v1/evidence/daily_summary.csv
# ekspor manual satu tanggal:
docker compose exec rbta-service python scripts/export_live_evidence.py --date 2026-10-16
```

File: `daily_summary.csv`, `daily_per_agent.csv`, `feature_quantiles_live.csv`,
`analyst_verdicts.csv`, `analyst_verdicts_summary.csv`. Pembanding drift fitur:
`artifacts/reference_feature_quantiles.json` di repo (partisi reference skripsi, terverifikasi
terhadap RobustScaler beku).

Label analyst: dashboard → **Review Queue** (semua ESCALATE + sampel 5% SUPPRESS/DIGEST per hari),
lalu label di halaman detail MetaAlert.

## 7. Membuat rilis (setelah bootstrap bagian 0)

Di laptop, setelah gate hijau dan commit sudah di `prod/final-dashboard-demo`:

```bash
git switch prod/final-dashboard-demo && git pull --ff-only
git tag -a release-2026.10.17 -m "rilis: <ringkasan>"
git push origin release-2026.10.17
```

Cron CT men-deploy dalam ±5 menit; pantau `tail -f ~/rbta/deploy/ct/cd.log`
(`DEPLOY ... (release-2026.10.17)` lalu `OK`). Commit tanpa tag tercatat `SKIP ... tanpa tag`.

## 8. Rollback

Matikan cron CD dulu (`crontab -e`, beri `#`): selama ujung branch masih bertag `release-*`,
skrip CD akan mem-fast-forward checkout yang di-rollback kembali ke rilis itu. Aktifkan lagi
setelah rilis perbaikan diberi tag.

```bash
cd ~/rbta && git log --oneline -5
git checkout <sha-rilis-sebelumnya>
cd deploy/ct && docker compose build && docker compose up -d
# state: docker compose down; docker volume rm rbta-ct-live; docker volume create rbta-ct-live;
#        docker run --rm -v rbta-ct-live:/s -v "$PWD":/b alpine tar xzf /b/live-backup-<tgl>.tgz -C /s
```
