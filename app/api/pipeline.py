from flask import current_app, jsonify
from flask_jwt_extended import jwt_required

from app.api import api_bp
from app.services.kafka_pipeline import is_kafka_enabled, kafka_health, worker_health


@api_bp.get("/pipeline/status")
@jwt_required()
def pipeline_status():
    if not is_kafka_enabled():
        return jsonify(
            success=True,
            enabled=False,
            status={"state": "disabled", "workers": []},
        )
    status = worker_health()
    broker = kafka_health()
    return jsonify(
        success=broker == "healthy" and status["state"] == "healthy",
        enabled=True,
        broker=broker,
        status=status,
        stale_after_seconds=current_app.config["KAFKA_WORKER_HEARTBEAT_SECONDS"] * 3,
    ), 200 if broker == "healthy" and status["state"] == "healthy" else 503
