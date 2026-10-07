from __future__ import annotations

from datetime import datetime, timedelta, timezone

from flask import jsonify
from flask_jwt_extended import jwt_required
from sqlalchemy import func, or_

from app import db
from app.api import api_bp
from app.models.alert import Alert
from app.models.event import Event


@api_bp.get("/network/summary")
@jwt_required()
def network_summary():
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    network_filter = or_(
        Event.event_type.ilike("%network%"),
        Event.event_type.ilike("%connection%"),
        Event.event_type.ilike("%firewall%"),
        Event.event_type.ilike("%flow%"),
        Event.event_type.ilike("%dns%"),
    )
    query = Event.query.filter(Event.timestamp >= since, network_filter)
    total = query.count()
    sources = (
        db.session.query(Event.source_ip, func.count(Event.id).label("count"))
        .filter(Event.timestamp >= since, network_filter, Event.source_ip.isnot(None))
        .group_by(Event.source_ip).order_by(func.count(Event.id).desc()).limit(10).all()
    )
    destinations = (
        db.session.query(Event.destination_ip, func.count(Event.id).label("count"))
        .filter(Event.timestamp >= since, network_filter, Event.destination_ip.isnot(None))
        .group_by(Event.destination_ip).order_by(func.count(Event.id).desc()).limit(10).all()
    )
    ports = (
        db.session.query(Event.destination_port, func.count(Event.id).label("count"))
        .filter(Event.timestamp >= since, network_filter, Event.destination_port.isnot(None))
        .group_by(Event.destination_port).order_by(func.count(Event.id).desc()).limit(10).all()
    )
    suspicious_ips = (
        db.session.query(Alert.source_ip, func.count(Alert.id).label("alert_count"))
        .filter(
            Alert.created_at >= since,
            Alert.source_ip.isnot(None),
            Alert.status.notin_(("RESOLVED", "FALSE_POSITIVE")),
        )
        .group_by(Alert.source_ip).order_by(func.count(Alert.id).desc()).limit(20).all()
    )
    recent = query.order_by(Event.timestamp.desc()).limit(50).all()
    active_sources = (
        db.session.query(func.count(func.distinct(Event.source_ip)))
        .filter(Event.timestamp >= since, network_filter, Event.source_ip.isnot(None)).scalar()
    ) or 0
    active_destinations = (
        db.session.query(func.count(func.distinct(Event.destination_ip)))
        .filter(Event.timestamp >= since, network_filter, Event.destination_ip.isnot(None)).scalar()
    ) or 0
    return jsonify(success=True, summary={
        "window": "24 hours",
        "network_events": total,
        "active_sources": active_sources,
        "active_destinations": active_destinations,
        "suspicious_sources": [
            {"ip": ip, "alert_count": count}
            for ip, count in suspicious_ips
        ],
        "top_sources": [{"ip": ip, "count": count} for ip, count in sources],
        "top_destinations": [{"ip": ip, "count": count} for ip, count in destinations],
        "top_destination_ports": [{"port": port, "count": count} for port, count in ports],
        "recent_events": [event.to_dict() for event in recent],
    })
