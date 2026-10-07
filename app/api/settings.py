from __future__ import annotations

from flask import current_app, jsonify
from flask_jwt_extended import jwt_required

from app import db
from app.api import api_bp
from app.services.kafka_pipeline import is_kafka_enabled, kafka_health, worker_health
from app.services.log_ingestion import get_ml_engine


@api_bp.get("/settings")
@jwt_required()
def get_settings():
    config = current_app.config
    model = get_ml_engine()
    pipeline = worker_health() if is_kafka_enabled() else {"state": "disabled", "workers": []}
    return jsonify(success=True, settings={
        "application": {
            "database": db.engine.dialect.name,
            "jwt_lifetime_minutes": config["JWT_ACCESS_TOKEN_EXPIRES"] // 60,
            "max_request_size_mb": round(config["MAX_CONTENT_LENGTH"] / (1024 * 1024), 2),
        },
        "detection": {
            "authentication_failures": config["AUTH_FAILURE_THRESHOLD"],
            "authentication_window_minutes": config["AUTH_WINDOW_MINUTES"],
            "network_port_threshold": config["NETWORK_PORT_THRESHOLD"],
            "network_window_minutes": config["NETWORK_WINDOW_MINUTES"],
            "ml_alert_threshold": config["ML_ANOMALY_ALERT_THRESHOLD"],
            "risk_thresholds": config["RISK_THRESHOLDS"],
            "alert_dedup_minutes": config["ALERT_DEDUP_MINUTES"],
        },
        "integrations": {
            "elasticsearch_enabled": bool(config["ELASTICSEARCH_URL"]),
            "elasticsearch_index": config["ELASTICSEARCH_INDEX"],
            "threat_intelligence_configured": bool(config["THREAT_INTEL_API_KEY"]),
            "syslog_enabled": config["ENABLE_SYSLOG"],
            "syslog_endpoint": f"{config['SYSLOG_HOST']}:{config['SYSLOG_PORT']}" if config["ENABLE_SYSLOG"] else None,
            "kafka_enabled": is_kafka_enabled(),
            "kafka_broker": kafka_health(),
            "event_pipeline": pipeline,
            "ml_model_available": model.available,
            "ml_model_version": model.version,
        },
    })
