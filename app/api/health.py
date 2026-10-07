from flask import current_app, jsonify
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app import db, socketio
from app.api import api_bp
from app.services.kafka_pipeline import is_kafka_enabled, kafka_health, worker_health
from app.services.log_ingestion import get_elk_service, get_ml_engine


@api_bp.get("/health")
def health():
    try:
        db.session.execute(text("SELECT 1"))
        database = "healthy"
    except SQLAlchemyError:
        db.session.rollback()
        database = "unavailable"
    elk = get_elk_service().health()
    model = "healthy" if get_ml_engine().available else "unavailable"
    syslog = "healthy" if current_app.extensions.get("syslog_server") else "disabled"
    broker = kafka_health()
    try:
        pipeline = worker_health() if is_kafka_enabled() else {"state": "disabled", "workers": []}
    except SQLAlchemyError:
        db.session.rollback()
        pipeline = {"state": "unavailable", "workers": []}
    result = {
        "application": "healthy",
        "database": database,
        "elasticsearch": elk,
        "ml_engine": model,
        "log_ingestion": "healthy",
        "websocket_service": "healthy" if socketio.server else "unavailable",
        "syslog_listener": syslog,
        "kafka_broker": broker,
        "event_worker": pipeline["state"],
    }
    healthy = database == "healthy" and (
        not is_kafka_enabled()
        or (broker == "healthy" and pipeline["state"] == "healthy")
    )
    return jsonify(success=healthy, components=result), 200 if healthy else 503
