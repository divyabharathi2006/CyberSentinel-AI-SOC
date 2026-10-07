from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_score, recall_score
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import create_app, db  # noqa: E402
from app.ml.feature_engineering import FEATURE_NAMES, FEATURE_VERSION, event_features  # noqa: E402
from app.models.model_version import ModelVersion  # noqa: E402

ARTIFACT = ROOT / "app" / "ml" / "models" / "artifacts"


def synthetic_baseline(count: int, seed: int = 42) -> list[dict]:
    rng = np.random.default_rng(seed)
    events = []
    for _ in range(count):
        events.append({
            "timestamp": datetime(2025, 3, 3, int(rng.integers(7, 19)), int(rng.integers(60)), tzinfo=timezone.utc),
            "event_type": str(rng.choice(["authentication", "network_connection", "application"])),
            "status": str(rng.choice(["success", "accepted", "success"])),
            "action": "observe", "source_port": int(rng.integers(49152, 65536)),
            "destination_port": int(rng.choice([443, 443, 443, 53])),
            "severity": str(rng.choice(["informational", "low"])),
            "message": "synthetic baseline",
        })
    return events


def load_training_events(csv_path: Path | None, count: int) -> tuple[list[dict], str]:
    if csv_path is None:
        return synthetic_baseline(count), "synthetic-baseline-v1"
    frame = pd.read_csv(csv_path)
    if frame.empty or "event_type" not in frame.columns:
        raise ValueError("Training CSV must be non-empty and include an event_type column")
    if len(frame) > 1_000_000:
        raise ValueError("Training CSV is limited to 1,000,000 rows")
    frame = frame.replace({np.nan: None})
    return frame.to_dict(orient="records"), csv_path.name


def train(csv_path: Path | None = None, count: int = 2000) -> dict:
    events, dataset_version = load_training_events(csv_path, count)
    rows = np.asarray([event_features(event) for event in events], dtype=np.float64)
    if rows.ndim != 2 or rows.shape[1] != len(FEATURE_NAMES) or not np.isfinite(rows).all():
        raise ValueError("Feature validation failed; training rows must contain finite engineered values")
    train_rows, holdout = train_test_split(rows, test_size=0.2, random_state=42)
    model = IsolationForest(
        n_estimators=200, contamination=0.04, random_state=42, n_jobs=-1,
    )
    model.fit(train_rows)
    normal_scores = model.decision_function(holdout)
    score_anomalous = max(0.0, min(1.0, 0.5 - normal_scores * 2.0))
    detected_normal = score_anomalous >= 0.65
    # The generated outlier probe is used only as a smoke evaluation of separation.
    probe = dict(events[0])
    probe.update({
        "event_type": "authentication_failure", "status": "failed",
        "source_port": 0, "destination_port": 1, "severity": "critical",
        "message": "synthetic evaluation probe",
    })
    probe_score = float(model.decision_function([event_features(probe)])[0])
    probe_anomaly = max(0.0, min(1.0, 0.5 - probe_score * 2.0))
    y_true = np.concatenate([np.zeros(len(holdout), dtype=int), np.ones(1, dtype=int)])
    y_pred = np.concatenate([detected_normal.astype(int), np.array([probe_anomaly >= 0.65], dtype=int)])
    metrics = {
        "holdout_size": int(len(holdout)),
        "synthetic_probe_anomaly_score": round(probe_anomaly, 4),
        "probe_detected": bool(probe_anomaly >= 0.65),
        "holdout_flag_rate": round(float(detected_normal.mean()), 4),
        "probe_evaluation_precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "probe_evaluation_recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "evaluation_note": "Unsupervised synthetic smoke evaluation only; not a production efficacy claim.",
    }
    version = "1.0.0"
    trained_at = datetime.now(timezone.utc)
    metadata = {
        "model_version": version,
        "algorithm": "IsolationForest",
        "trained_at": trained_at.isoformat(),
        "dataset_version": dataset_version,
        "feature_version": FEATURE_VERSION,
        "feature_names": FEATURE_NAMES,
        "training_records": int(len(rows)),
        "metrics": metrics,
    }
    ARTIFACT.mkdir(parents=True, exist_ok=True)
    model_path = ARTIFACT / "isolation_forest.joblib"
    metadata_path = ARTIFACT / "metadata.json"
    temp_model = ARTIFACT / "isolation_forest.joblib.tmp"
    temp_metadata = ARTIFACT / "metadata.json.tmp"
    joblib.dump(model, temp_model)
    temp_metadata.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    temp_model.replace(model_path)
    temp_metadata.replace(metadata_path)

    app = create_app()
    with app.app_context():
        db.create_all()
        existing = ModelVersion.query.filter_by(version=version).first()
        if existing:
            existing.trained_at = trained_at
            existing.metrics = metrics
            existing.artifact_path = str(model_path)
            existing.dataset_version = dataset_version
        else:
            db.session.add(ModelVersion(
                version=version, algorithm="IsolationForest", dataset_version=dataset_version,
                feature_version=FEATURE_VERSION, metrics=metrics, artifact_path=str(model_path),
                trained_at=trained_at,
            ))
        db.session.commit()
    return metadata


def main() -> int:
    parser = argparse.ArgumentParser(description="Train the CyberSentinel Isolation Forest anomaly model")
    parser.add_argument("--dataset", type=Path, help="Optional CSV with normalized event columns; otherwise use safe synthetic baseline")
    parser.add_argument("--count", type=int, default=2000, help="Synthetic normal records when no CSV is provided")
    args = parser.parse_args()
    if args.dataset and not args.dataset.is_file():
        parser.error("--dataset must be an existing CSV file")
    if not 200 <= args.count <= 100_000:
        parser.error("--count must be between 200 and 100000")
    result = train(args.dataset, args.count)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
