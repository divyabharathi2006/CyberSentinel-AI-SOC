from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from flask import jsonify
from flask_jwt_extended import jwt_required
from sqlalchemy import func

from app import db
from app.api import api_bp
from app.models.alert import Alert
from app.models.event import Event
from app.models.incident import Incident
from app.services.log_ingestion import get_ml_engine


@api_bp.get("/dashboard/summary")
@jwt_required()
def dashboard_summary():
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=24)
    event_count = Event.query.count()
    recent_events = Event.query.filter(Event.timestamp >= now - timedelta(minutes=1)).count()
    alert_counts = dict(
        db.session.query(Alert.severity, func.count(Alert.id))
        .filter(Alert.status.notin_(("RESOLVED", "FALSE_POSITIVE")))
        .group_by(Alert.severity)
        .all()
    )
    if db.engine.dialect.name == "postgresql":
        hour_bucket = func.date_trunc("hour", Event.timestamp)
        hourly_rows = (
            db.session.query(hour_bucket, func.count(Event.id))
            .filter(Event.timestamp >= since)
            .group_by(hour_bucket)
            .order_by(hour_bucket)
            .all()
        )
    else:
        hour_bucket = func.strftime("%Y-%m-%dT%H:00:00", Event.timestamp)
        hourly_rows = (
            db.session.query(hour_bucket, func.count(Event.id))
            .filter(Event.timestamp >= since)
            .group_by(hour_bucket)
            .order_by(hour_bucket)
            .all()
        )
    incidents = dict(db.session.query(Incident.status, func.count(Incident.id)).group_by(Incident.status).all())
    top_ips = (
        db.session.query(Event.source_ip, func.count(Event.id).label("total"))
        .filter(Event.source_ip.isnot(None), Event.timestamp >= since)
        .group_by(Event.source_ip).order_by(func.count(Event.id).desc()).limit(10).all()
    )
    top_types = (
        db.session.query(Event.event_type, func.count(Event.id).label("total"))
        .filter(Event.timestamp >= since).group_by(Event.event_type)
        .order_by(func.count(Event.id).desc()).limit(10).all()
    )
    top_destinations = (
        db.session.query(Event.destination_ip, func.count(Event.id).label("total"))
        .filter(Event.destination_ip.isnot(None), Event.timestamp >= since)
        .group_by(Event.destination_ip).order_by(func.count(Event.id).desc()).limit(10).all()
    )
    top_users = (
        db.session.query(Event.username, func.count(Event.id).label("total"))
        .filter(Event.username.isnot(None), Event.timestamp >= since)
        .group_by(Event.username).order_by(func.count(Event.id).desc()).limit(10).all()
    )
    top_ports = (
        db.session.query(Event.destination_port, func.count(Event.id).label("total"))
        .filter(Event.destination_port.isnot(None), Event.timestamp >= since)
        .group_by(Event.destination_port).order_by(func.count(Event.id).desc()).limit(10).all()
    )
    threat_categories = (
        db.session.query(Alert.rule_name, func.count(Alert.id).label("total"))
        .filter(Alert.created_at >= since)
        .group_by(Alert.rule_name).order_by(func.count(Alert.id).desc()).limit(10).all()
    )
    active_suspicious_ips = (
        db.session.query(func.count(func.distinct(Alert.source_ip)))
        .filter(
            Alert.source_ip.isnot(None),
            Alert.status.notin_(("RESOLVED", "FALSE_POSITIVE")),
        ).scalar()
    ) or 0
    alert_hours: dict[str, int] = defaultdict(int)
    for created_at, in db.session.query(Alert.created_at).filter(Alert.created_at >= since).limit(5000).all():
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        bucket = created_at.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0).isoformat()
        alert_hours[bucket] += 1
    return jsonify(success=True, summary={
        "total_events": event_count,
        "events_per_minute": recent_events,
        "critical_alerts": alert_counts.get("critical", 0),
        "high_alerts": alert_counts.get("high", 0),
        "medium_alerts": alert_counts.get("medium", 0),
        "low_alerts": alert_counts.get("low", 0),
        "open_incidents": sum(count for status, count in incidents.items() if status not in {"Resolved", "Closed"}),
        "resolved_incidents": incidents.get("Resolved", 0) + incidents.get("Closed", 0),
        "detection_rate": round(sum(alert_counts.values()) * 100 / event_count, 2) if event_count else 0.0,
        "anomaly_count": Alert.query.filter(Alert.anomaly_score.isnot(None), Alert.anomaly_score >= 0.65).count(),
        "active_suspicious_ips": active_suspicious_ips,
        "events_over_time": [{"hour": str(hour), "count": count} for hour, count in hourly_rows],
        "alerts_over_time": [{"hour": hour, "count": count} for hour, count in sorted(alert_hours.items())],
        "severity_distribution": alert_counts,
        "top_source_ips": [{"ip": ip, "count": count} for ip, count in top_ips],
        "top_destination_ips": [{"ip": ip, "count": count} for ip, count in top_destinations],
        "top_users": [{"username": username, "count": count} for username, count in top_users],
        "top_destination_ports": [{"port": port, "count": count} for port, count in top_ports],
        "top_event_types": [{"event_type": event_type, "count": count} for event_type, count in top_types],
        "threat_categories": [{"category": name, "count": count} for name, count in threat_categories],
        "incidents_by_status": incidents,
        "ml_available": get_ml_engine().available,
        "window": "24 hours",
    })
