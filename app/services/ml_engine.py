from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import joblib

from app.ml.feature_engineering import FEATURE_VERSION, event_features

logger = logging.getLogger(__name__)


class MLEngine:
    def __init__(self, model_path: str, metadata_path: str):
        self.model_path = Path(model_path)
        self.metadata_path = Path(metadata_path)
        self._model = None
        self._metadata: dict[str, Any] = {}
        self._load_error: str | None = None
        self._load()

    def _load(self) -> None:
        if not self.model_path.is_file():
            self._load_error = "No trained anomaly model is installed"
            return
        try:
            self._model = joblib.load(self.model_path)
            if self.metadata_path.is_file():
                self._metadata = json.loads(self.metadata_path.read_text(encoding="utf-8"))
            if self._metadata.get("feature_version") != FEATURE_VERSION:
                raise ValueError("The installed model feature version is incompatible")
            self._load_error = None
        except (OSError, ValueError, TypeError, EOFError) as exc:
            logger.exception("Anomaly model could not be loaded")
            self._model = None
            self._load_error = str(exc)

    @property
    def available(self) -> bool:
        return self._model is not None

    @property
    def version(self) -> str | None:
        return self._metadata.get("model_version") if self.available else None

    def predict(self, event: dict[str, Any]) -> dict[str, Any]:
        if not self._model:
            return {"available": False, "reason": self._load_error}
        features = event_features(event)
        raw = float(self._model.decision_function([features])[0])
        anomaly = max(0.0, min(1.0, 0.5 - raw * 2.0))
        return {
            "available": True,
            "anomaly_score": round(anomaly, 4),
            "risk_score": round(anomaly * 100),
            "classification": "anomalous" if anomaly >= 0.65 else "within_baseline",
            "model_version": self.version or "unknown",
            "feature_summary": dict(zip(
                ("hour_utc", "weekend", "source_port", "destination_port", "auth_failure", "auth_success", "network_event", "privilege_event", "high_severity", "message_length"),
                features,
            )),
        }
