# RBTA + Isolation Forest untuk Mitigasi Alert Fatigue Wazuh

Implementasi penelitian skripsi **Rule-Based Temporal Aggregation (RBTA) dan Isolation Forest
untuk Mitigasi Alert Fatigue pada Log Keamanan SIEM Wazuh**.

Sistem ini mengurangi dan memprioritaskan unit triase. Alert bukan otomatis serangan, anomaly
score bukan label serangan, dan setiap MetaAlert harus tetap dapat ditelusuri ke bukti mentahnya.

## Alur

```text
alert Wazuh (JSONL / Indexer)
  -> kanonisasi (CanonicalRawAlert, timestamp UTC)
  -> RBTA: bucket (agent_id, rule_group_primary) + Elastic Time Window per agent
  -> MetaAlert
  -> 7 fitur
  -> Isolation Forest beku (RobustScaler, 200 tree)
  -> threshold Tukey IQR + Decision Matrix
  -> history, raw evidence, outbox -> API -> dashboard / Telegram
```

Aturan metodologi yang dikunci:

- Kunci bucket RBTA `(agent_id, rule_group_primary)`; state window temporal lokal per agent.
- Alert valid tidak pernah dibuang hanya karena datang tidak berurutan.
- Input model tepat tujuh fitur: `max_severity`, `mitre_tactic_count`,
  `critical_mitre_tactic_present`, `alert_count_log`, `rule_diversity_shannon`,
  `severity_dispersion`, `agent_criticality`.
- Isolation Forest unsupervised; replay dan evaluasi memakai model beku tanpa refit.
- Prioritas ditentukan di luar model: Tukey (Q3 + 1.5 IQR) lalu Decision Matrix
  (`CRITICAL`/`SUSPICIOUS` -> `ESCALATE`, `NOISE_HIGH` -> `DAILY_DIGEST`, `NOISE` -> `SUPPRESS`).
- ARR mengukur reduksi unit triase, bukan akurasi deteksi. Context purity mengukur konsistensi
  agregasi. Silhouette dibandingkan dengan baseline permutasi, bukan ukuran akurasi serangan.

Rincian lengkap ada di [`docs/research-spec/`](docs/research-spec/README.md).

## Struktur repository

| Path | Isi |
| --- | --- |
| `src/etl`, `src/ingestion` | Kanonisasi alert Wazuh, client Indexer dan custom API, checkpoint historis |
| `src/rbta` | Engine RBTA, state temporal per agent, reorder buffer |
| `src/features` | Ekstraktor tujuh fitur |
| `src/model` | Training reference, registry artefak, scoring pipeline, Tukey, Decision Matrix |
| `src/evaluation` | ARR, sensitivitas delta-t, ablation, ketahanan noise, runtime, Silhouette |
| `src/runtime` | Service live, state durable (SQLite), raw evidence, replay controller, live worker, dispatcher Telegram |
| `src/api` | FastAPI: endpoint operasional, dashboard, replay |
| `src/research` | Orkestrator penelitian end-to-end (`main.py`) |
| `dashboard/` | Dashboard React + Vite + TypeScript |
| `tests/` | Unit dan integration test backend |
| `deploy/ct/` | Deployment produksi (Docker) di CT Proxmox kampus |
| `deploy/local/` | Compose lokal untuk Docker Desktop (opsional) |
| `scripts/` | Benchmark replay, pembuatan dataset demo, validasi deployment |
| `examples/`, `notebooks/` | Contoh pemakaian dan EDA dataset |
| `archive/` | Kode dan konfigurasi lama yang tidak dipakai lagi |

## Menjalankan secara lokal (Windows, tanpa Docker)

Backend:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"

$env:RBTA_API_KEY = "<token-lokal>"
$env:RBTA_MODEL_VERSION = "rbta-if-v1"
$env:RBTA_MODEL_REGISTRY_DIR = "models"
$env:RBTA_REPLAY_DATA_DIR = "<folder export .jsonl Wazuh>"
$env:RBTA_PORT = "8010"
python -m src.api.server
```

Frontend (terminal kedua):

```powershell
Set-Location dashboard
npm ci
npm run dev -- --host 127.0.0.1
```

Dashboard tersedia di `http://127.0.0.1:5173/dashboard/` dan mem-proxy API ke port 8010.
Daftar variabel environment ada di [`.env.example`](.env.example); panduan lengkap di
[`docs/deployment/NATIVE-LOCAL-RUNBOOK.md`](docs/deployment/NATIVE-LOCAL-RUNBOOK.md).

Folder model (`models/`) dan dataset tidak ikut git. Dataset dibaca dari `RBTA_REPLAY_DATA_DIR`;
hanya file `.jsonl` dan `.jsonl.gz` yang di-ingest, sidecar `.meta` diabaikan.

## Orkestrator penelitian

```powershell
python main.py --input <file-atau-folder-jsonl> --delta-t auto --seed 42
```

Hasil run (konfigurasi, hash, metrik, artefak model) ditulis ke `artifacts/research-runs/`.
`--fixture` menjalankan data sintetis untuk smoke test saja, bukan untuk hasil penelitian.

## Test

```powershell
python -m pytest -q

Set-Location dashboard
npm run lint
npm run typecheck
npm test
npm run build
```

## Deployment

Produksi berjalan sebagai satu container (backend + dashboard statis) di CT Proxmox kampus,
dengan polling Wazuh Indexer dan notifikasi Telegram. Langkah setup dan auto-update ada di
[`deploy/ct/README.md`](deploy/ct/README.md).

## Dokumentasi lain

- [`docs/research-spec/`](docs/research-spec/README.md) — spesifikasi metodologi dan arsitektur.
- [`docs/deployment/LIVE-STATE-RECOVERY.md`](docs/deployment/LIVE-STATE-RECOVERY.md) — kontrak pemulihan state live/replay.
- [`docs/deployment/FLAT-API-FREEZE.md`](docs/deployment/FLAT-API-FREEZE.md) — kontrak event custom API kampus.
- [`docs/demo/SIDANG-RUNBOOK.md`](docs/demo/SIDANG-RUNBOOK.md) — runbook demo sidang.
- [`docs/thesis/`](docs/thesis/) — kerangka Bab IV–V.
