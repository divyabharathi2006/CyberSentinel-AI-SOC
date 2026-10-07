from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from flask import current_app, jsonify
from flask_jwt_extended import jwt_required

from app.api import api_bp
from app.models.alert import Alert
from app.services.log_ingestion import get_ml_engine


@api_bp.get("/ml/analytics")
@jwt_required()
def ml_analytics():
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=24)
    alerts = (
        Alert.query.filter(Alert.anomaly_score.isnot(None), Alert.created_at >= since)
        .order_by(Alert.created_at.desc()).limit(1000).all()
    )
    threshold = current_app.config["ML_ANOMALY_ALERT_THRESHOLD"]
    hourly_counts: dict[str, int] = defaultdict(int)
    for alert in alerts:
        created = alert.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        hourly_counts[created.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0).isoformat()] += 1

    model = get_ml_engine()
    return jsonify(success=True, analytics={
        "model_available": model.available,
        "model_version": model.version,
        "alert_threshold": threshold,
        "sample_count": len(alerts),
        "anomaly_alert_count": sum(alert.anomaly_score >= threshold for alert in alerts),
        "average_anomaly_score": round(sum(alert.anomaly_score for alert in alerts) / len(alerts), 4) if alerts else None,
        "score_distribution": {
            "below_threshold": sum(alert.anomaly_score < threshold for alert in alerts),
            "at_or_above_threshold": sum(alert.anomaly_score >= threshold for alert in alerts),
        },
        "alerts_over_time": [{"hour": hour, "count": count} for hour, count in sorted(hourly_counts.items())],
        "recent_alerts": [{
            "id": alert.id,
            "created_at": alert.created_at.isoformat(),
            "title": alert.title,
            "severity": alert.severity,
            "anomaly_score": alert.anomaly_score,
            "classification": "potential anomaly" if alert.anomaly_score >= threshold else "below alert threshold",
            "model_version": alert.model_version,
        } for alert in alerts[:50]],
        "interpretation": "Anomaly scores are advisory signals, not proof of malicious activity. These statistics cover alerts with a stored ML score, not all ingested events.",
    })
