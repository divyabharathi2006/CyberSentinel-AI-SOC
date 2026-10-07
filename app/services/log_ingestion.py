from __future__ import annotations

import csv
import io
import json
import logging
from typing import Any

from flask import current_app

from app import db, socketio
from app.models.event import Event
from app.rules.rule_engine import evaluate_event
from app.services.alert_service import create_alert
from app.services.elk_service import ElkService
from app.services.log_normalizer import normalize_event
from app.services.ml_engine import MLEngine

logger = logging.getLogger(__name__)


def get_ml_engine() -> MLEngine:
    engine = current_app.extensions.get("cybersentinel_ml")
    if engine is None:
        engine = MLEngine(current_app.config["ML_MODEL_PATH"], current_app.config["ML_METADATA_PATH"])
        current_app.extensions["cybersentinel_ml"] = engine
    return engine


def get_elk_service() -> ElkService:
    service = current_app.extensions.get("cybersentinel_elk")
    if service is None:
        service = ElkService(
            current_app.config["ELASTICSEARCH_URL"],
            current_app.config["ELASTICSEARCH_USERNAME"],
            current_app.config["ELASTICSEARCH_PASSWORD"],
            current_app.config["ELASTICSEARCH_INDEX"],
        )
        current_app.extensions["cybersentinel_elk"] = service
    return service


def ingest_one(
    payload: dict[str, Any],
    actor_id: int | None,
    default_source: str = "api",
    commit: bool = True,
) -> tuple[Event, list]:
    normalized = normalize_event(payload, default_source=default_source)
    event = Event(**normalized)
    db.session.add(event)
    db.session.flush()

    ml_result = get_ml_engine().predict(event.to_dict())
    created_alerts = []
    for detection in evaluate_event(event):
        alert = create_alert(detection, event, ml_result)
        if alert:
            created_alerts.append(alert)
    if ml_result.get("available") and ml_result.get("anomaly_score", 0) >= current_app.config["ML_ANOMALY_ALERT_THRESHOLD"]:
        created_alerts.append(create_alert({
            "rule_id": "ML-ANOMALY-001",
            "rule_name": "Isolation Forest anomaly signal",
            "title": "Unusual event pattern requires analyst review",
            "description": f"The trained model assigned an anomaly score of {ml_result['anomaly_score']:.2f}. An anomaly is not proof of malicious activity.",
            "severity": "high" if ml_result["anomaly_score"] >= 0.95 else "medium",
            "confidence": 0.60,
            "event_ids": [event.id],
            "frequency": 1,
            "mitre": [],
            "recommended_action": "Review the event and its baseline context; validate the model signal with independent telemetry.",
        }, event, ml_result))

    if commit:
        db.session.commit()
        publish_ingested(event, created_alerts)
    else:
        db.session.flush()
    return event, created_alerts


def publish_ingested(event: Event, created_alerts: list) -> None:
    indexed = get_elk_service().index_event(event.to_dict())
    if not indexed:
        logger.info("Event stored in relational database; Elasticsearch indexing was unavailable")
    for alert in created_alerts:
        socketio.emit("new_alert", alert.to_dict(), namespace="/soc")
    socketio.emit(
        "new_event",
        {"id": event.id, "event_type": event.event_type, "severity": event.severity},
        namespace="/soc",
    )


def parse_upload(filename: str, content: bytes) -> list[dict]:
    if len(content) > current_app.config["MAX_CONTENT_LENGTH"]:
        raise ValueError("Uploaded file exceeds the configured request size limit")
    text = content.decode("utf-8-sig")
    suffix = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if suffix == "json":
        parsed = json.loads(text)
        records = parsed if isinstance(parsed, list) else [parsed]
    elif suffix in {"jsonl", "ndjson"}:
        records = [json.loads(line) for line in text.splitlines() if line.strip()]
    elif suffix == "csv":
        records = list(csv.DictReader(io.StringIO(text)))
    elif suffix in {"log", "txt"}:
        from app.services.log_normalizer import parse_syslog_line

        records = [parse_syslog_line(line) for line in text.splitlines() if line.strip()]
    else:
        raise ValueError("Supported file types are JSON, JSONL, CSV, LOG, and TXT")
    if not isinstance(records, list) or len(records) > 1000:
        raise ValueError("File must contain at most 1000 event records")
    return records
