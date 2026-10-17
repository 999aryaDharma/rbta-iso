# Deploy produksi ke CT Proxmox (Docker)

Satu container: backend FastAPI + dashboard statis (`/dashboard/`).
Konfigurasi deployment ASUS yang lama ada di `archive/asus/` sebagai arsip.

## 1. Siapkan CT (manual, sekali saja)

1. Buat LXC: Ubuntu 24.04, 2 vCPU / 4 GB RAM / 30 GB disk, IP statis + DNS,
   aktifkan **nesting** (`pct set <CTID> --features nesting=1`), user + SSH.
2. Install Docker + compose plugin di CT:
   ```bash
   apt-get update && apt-get install -y docker.io docker-compose-plugin
   docker compose version
   ```
3. Pastikan CT mencapai Indexer dan internet:
   ```bash
   ping -c2 172.16.83.207
   curl -s -o /dev/null -w '%{http_code}\n' https://api.telegram.org
   ```

## 2. Kode + model (manual)

```bash
git clone -b prod/final-dashboard-demo <repo-url> rbta && cd rbta
mkdir -p models deploy/ct/certs
```

`models/` TIDAK ikut git — transfer manual dari laptop (baca-saja):

```powershell
scp -r models/rbta-if-v1 root@<ip-ct>:~/rbta/models/
scp wazuh-indexer-leaf.pem root@<ip-ct>:~/rbta/deploy/ct/certs/
```

## 3. Kredensial segar (manual, di CT saja)

```bash
cp deploy/ct/.env.example deploy/ct/.env
nano deploy/ct/.env   # isi SEMUA nilai ganti-*: password reader HASIL ROTASI,
                      # RBTA_API_KEY baru, token+chat Telegram
```

Atur `RBTA_MODEL_HOST_DIR` ke path absolut models di CT.
Jangan commit `deploy/ct/.env` (di-ignore).

## 4. Build + up (di CT)

```bash
cd deploy/ct
docker compose build
docker compose up -d
# WAJIB sekali per volume baru: volume dibuat milik root, container jalan
# sebagai UID 10001 — tanpa ini backend crash PermissionError state.json.lock:
docker run --rm -v rbta-ct-live:/s -v rbta-ct-archive:/a \
  alpine chown -R 10001:10001 /s /a
docker compose restart rbta-service
sleep 45
curl -s http://127.0.0.1:8010/ready
```

Verifikasi live (ganti `<key>` dengan RBTA_API_KEY produksi):

```bash
curl -s -H "Authorization: Bearer <key>" \
  http://127.0.0.1:8010/api/v1/live/status | python3 -m json.tool
```

Harapan: `worker_alive:true`, `consecutive_failures:0`,
`live_model_version:"rbta-if-v1"`. Buka dashboard:
`http://<ip-ct>:8010/dashboard/live`.

## 5. Operasi

```bash
docker compose logs -f rbta-service   # log worker/siklus
docker compose down && docker compose up -d --build   # update (habis git pull)
docker volume ls | grep rbta-ct       # state (live) + arsip (archive) persisten
```

## 6. Auto-deploy (CD pull-based)

CT yang menarik, bukan GitHub yang mendorong (IP kampus privat tak
terjangkau runner publik). Cron tiap 5 menit menjalankan
`deploy/ct/auto-update.sh`: bila HEAD berubah → pull, rebuild, up,
cek `/ready`. Push ke branch = deploy dalam ±5 menit.
Tulis `[skip cd]` di pesan commit untuk melewati satu rilis
(mis. commit docs tanpa rebuild).

Pasang sekali di CT:

```bash
chmod +x ~/rbta/deploy/ct/auto-update.sh
(crontab -l 2>/dev/null; echo "*/5 * * * * RBTA_HOST_PORT=8010 bash $HOME/rbta/deploy/ct/auto-update.sh >> $HOME/rbta/deploy/ct/cd.log 2>&1") | crontab -
tail -f ~/rbta/deploy/ct/cd.log   # pantau hasil tiap jadwal
```

CI (`/.github/workflows/ci.yml`, Ubuntu publik) berjalan tiap push:
backend `pytest`, frontend `lint + typecheck + vitest`. CD di CT
sengaja tidak menunggu CI hijau — branch ini rilis manual peneliti;
jangan push kode yang belum lolos test lokal.

Backup berkala: `docker run --rm -v rbta-ct-live:/s -v $PWD:/b
alpine tar czf /b/live-backup.tgz -C /s .` (sama untuk `rbta-ct-archive`).

## Batas yang diketahui

- Image pertama kali di-build 2026-10-04 di CT (`rbta-service:ct`):
  base `python:3.13-slim` (3.11 tak punya wheel numpy 2.5.x),
  `scikit-learn==1.9.0` di `pyproject.toml` + `constraints.txt`
  (model `rbta-if-v1` dilatih 1.7.2 — ada `InconsistentVersionWarning`
  saat load, sudah terbukti stabil di semua test lokal + shadow run).
- Pin TLS = leaf interim; ganti ke CA permanen bila server menerbitkan ulang.
- Retensi arsip `rbta-ct-archive` belum otomatis — jadwalkan hapus manual.
