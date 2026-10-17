"""Bangun artifacts/reference_feature_quantiles.json dari partisi *reference* run skripsi (T6).

Sumber dan cara rekonstruksi (sekali jalan, hasilnya di-commit):

* Korpus lama = CSV yang dipakai ``docs/thesis/hasil-run-20261001/scripts/run_old.py``
  (sha256 harus ``079c47e3...``, sama dengan ``old_corpus_provenance.json``), dimuat dengan
  loader run itu (``scripts/loaders.py``, canonicalizer repo yang sama).
* Partisi reference = 60% pertama alert setelah sort kronologis, persis
  ``src/research/orchestrator.py``; diagregasi dengan ``BatchResearchRunner(Δt=10 menit,
  adaptive=True)`` seperti run skripsi (``selected_delta_t_minutes = 10``).
* Verifikasi sebelum menulis: jumlah MetaAlert harus sama dengan ``training_row_count`` model,
  dan RobustScaler yang di-fit ulang pada fitur hasil rekonstruksi harus memberi center_
  (median) dan scale_ (IQR) yang sama dengan ``robust_scaler.joblib`` beku. Model tidak diubah
  atau disimpan ulang; scaler baru hanya dipakai untuk pembandingan.

Kuantil (Q1, median, Q3, p95) memakai interpolasi linear pandas (sama dengan ekspor live).

    python scripts/build_reference_feature_quantiles.py --corpus <old.csv.gz>
"""

import argparse
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import sys

import joblib
import numpy as np
from sklearn.preprocessing import RobustScaler

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from src.features.extractor import FEATURE_COLUMNS  # noqa: E402
from src.runners.batch_runner import BatchResearchRunner  # noqa: E402

THESIS_RUN = REPO / "docs" / "thesis" / "hasil-run-20261001"
OLD_CORPUS_SHA256 = "079c47e3772fed5a4cce3cf2d1e9c6b98ff4e5a15433c5acb049a81c4a95b5dd"
QUANTILES = {"q1": 0.25, "median": 0.50, "q3": 0.75, "p95": 0.95}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--corpus", required=True, type=Path)
    parser.add_argument("--model-dir", type=Path, default=THESIS_RUN / "model")
    parser.add_argument("--out", type=Path, default=REPO / "artifacts" / "reference_feature_quantiles.json")
    args = parser.parse_args()

    sys.path.insert(0, str(THESIS_RUN / "scripts"))
    from loaders import load_old_csv  # loader run skripsi (tidak ikut git)

    metadata = json.loads((args.model_dir / "metadata.json").read_text(encoding="utf-8"))
    alerts, prov = load_old_csv(args.corpus)
    if prov["sha256"] != OLD_CORPUS_SHA256:
        raise SystemExit(f"Korpus bukan korpus skripsi: sha256={prov['sha256']}")
    sorted_alerts = sorted(alerts, key=lambda alert: alert.timestamp)
    reference = sorted_alerts[: int(len(sorted_alerts) * 0.60)]
    del alerts, sorted_alerts

    result = BatchResearchRunner(base_delta_t=timedelta(minutes=10), adaptive=True).run(reference)
    features = result.features_df[list(FEATURE_COLUMNS)]
    if len(features) != metadata["training_row_count"]:
        raise SystemExit(f"Jumlah MetaAlert {len(features)} != training_row_count {metadata['training_row_count']}")

    frozen = joblib.load(args.model_dir / "robust_scaler.joblib")
    refit = RobustScaler().fit(features)
    if not (np.allclose(refit.center_, frozen.center_, rtol=0, atol=1e-12)
            and np.allclose(refit.scale_, frozen.scale_, rtol=0, atol=1e-12)):
        raise SystemExit("Rekonstruksi tidak cocok dengan robust_scaler.joblib beku; tidak ditulis")

    out = {
        "description": "Kuantil 7 fitur partisi reference run skripsi (data latih rbta-if-thesis-v1).",
        "source": {
            "corpus_sha256": prov["sha256"],
            "model_version": metadata["model_version"],
            "model_sha256": hashlib.sha256((args.model_dir / "isolation_forest.joblib").read_bytes()).hexdigest(),
            "git_commit": metadata["git_commit"],
            "partition": "reference (60% pertama, kronologis)",
            "partition_period": [metadata["training_period_start"], metadata["training_period_end"]],
            "delta_t_minutes": 10,
            "adaptive": True,
            "n_raw": len(reference),
            "n_meta": len(features),
            "verified_against_frozen_robust_scaler": True,
            "builder": "scripts/build_reference_feature_quantiles.py",
        },
        "quantiles": {
            feature: {name: float(features[feature].quantile(q)) for name, q in QUANTILES.items()}
            for feature in FEATURE_COLUMNS
        },
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(f"OK {len(features)} MetaAlert reference -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
