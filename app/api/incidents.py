from __future__ import annotations

from datetime import datetime, timezone
from math import ceil

from flask import jsonify, request
from flask_jwt_extended import jwt_required

from app import db
from app.api import api_bp
from app.models.alert import AlertEvent
from app.models.event import Event
from app.models.incident import Incident
from app.models.user import User
from app.services.incident_service import create_incident, update_incident
from app.services.log_ingestion import get_ml_engine
from app.utils.security import actor_id, request_ip, roles_required


@api_bp.get("/incidents")
@jwt_required()
def list_incidents():
    query = Incident.query
    if request.args.get("status"):
        query = query.filter_by(status=request.args["status"])
    page = max(1, request.args.get("page", 1, type=int))
    per_page = min(100, max(1, request.args.get("per_page", 50, type=int)))
    pagination = query.order_by(Incident.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    return jsonify(success=True, items=[incident.to_dict() for incident in pagination.items], pagination={"page": page, "per_page": per_page, "total": pagination.total, "pages": ceil(pagination.total / per_page)})


@api_bp.post("/incidents")
@roles_required("Admin", "SOC Analyst", "Security Manager")
def create_incident_route():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(success=False, error={"code": "INVALID_REQUEST", "message": "A JSON object is required"}), 400
    if not isinstance(payload.get("title"), str) or not isinstance(payload.get("description"), str):
        return jsonify(success=False, error={"code": "INVALID_REQUEST", "message": "title and description must be strings"}), 400
    alert_ids = payload.get("alert_ids", [])
    if not isinstance(alert_ids, list) or len(alert_ids) > 100 or any(not isinstance(item, int) for item in alert_ids):
        return jsonify(success=False, error={"code": "INVALID_REQUEST", "message": "alert_ids must be a list of at most 100 integer IDs"}), 400
    try:
        incident = create_incident(
            payload.get("title", ""), payload.get("description", ""),
            payload.get("severity", "medium"), alert_ids, actor_id(), request_ip(),
        )
        db.session.commit()
    except ValueError as exc:
        db.session.rollback()
        return jsonify(success=False, error={"code": "INVALID_REQUEST", "message": str(exc)}), 400
    return jsonify(success=True, incident=incident.to_dict()), 201


@api_bp.get("/incidents/<int:incident_id>")
@jwt_required()
def get_incident(incident_id: int):
    incident = db.session.get(Incident, incident_id)
    if not incident:
        return jsonify(success=False, error={"code": "NOT_FOUND", "message": "Incident not found"}), 404
    return jsonify(success=True, incident=incident.to_dict(), alerts=[link.alert.to_dict() for link in incident.alert_links])


@api_bp.get("/timeline/<int:incident_id>")
@jwt_required()
def incident_timeline(incident_id: int):
    incident = db.session.get(Incident, incident_id)
    if not incident:
        return jsonify(success=False, error={"code": "NOT_FOUND", "message": "Incident not found"}), 404

    alert_ids = [link.alert_id for link in incident.alert_links]
    alerts = [link.alert for link in incident.alert_links if link.alert]
    linked_event_ids = {
        event_id
        for (event_id,) in db.session.query(AlertEvent.event_id).filter(AlertEvent.alert_id.in_(alert_ids)).all()
    } if alert_ids else set()
    linked_events = Event.query.filter(Event.id.in_(linked_event_ids)).all() if linked_event_ids else []

    items = [{
        "kind": "incident",
        "at": incident.created_at.isoformat(),
        "title": "Incident created",
        "detail": incident.title,
        "incident_id": incident.id,
    }]
    for entry in incident.timeline or []:
        items.append({
            "kind": "incident_update",
            "at": entry.get("at", incident.created_at.isoformat()),
            "title": f"Incident {entry.get('action', 'updated')}",
            "detail": ", ".join(entry.get("fields", [])),
            "incident_id": incident.id,
        })
    for note in incident.notes or []:
        items.append({
            "kind": "analyst_note",
            "at": note.get("created_at", incident.created_at.isoformat()),
            "title": "Analyst note",
            "detail": note.get("note", ""),
            "incident_id": incident.id,
        })
    for event in linked_events:
        items.append({
            "kind": "event",
            "at": event.timestamp.isoformat(),
            "title": f"{event.event_type} event",
            "detail": event.message or event.status or "No event details",
            "event_id": event.id,
            "severity": event.severity,
            "source_ip": event.source_ip,
        })
    for alert in alerts:
        items.append({
            "kind": "alert",
            "at": alert.created_at.isoformat(),
            "title": alert.title,
            "detail": f"{alert.rule_name} · {alert.status}",
            "alert_id": alert.id,
            "severity": alert.severity,
        })

    def timestamp_key(item: dict) -> datetime:
        try:
            parsed = datetime.fromisoformat(item["at"].replace("Z", "+00:00"))
        except (TypeError, ValueError):
            parsed = incident.created_at
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed

    items.sort(key=timestamp_key)
    return jsonify(
        success=True,
        incident_id=incident.id,
        incident_title=incident.title,
        timeline=items,
        event_count=len(linked_events),
        alert_count=len(alerts),
        ml_available=get_ml_engine().available,
    )


@api_bp.patch("/incidents/<int:incident_id>")
@roles_required("Admin", "SOC Analyst", "Security Manager")
def patch_incident(incident_id: int):
    incident = db.session.get(Incident, incident_id)
    if not incident:
        return jsonify(success=False, error={"code": "NOT_FOUND", "message": "Incident not found"}), 404
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(success=False, error={"code": "INVALID_REQUEST", "message": "A JSON object is required"}), 400
    if "assigned_to_id" in payload and payload["assigned_to_id"] is not None:
        assignee = db.session.get(User, payload["assigned_to_id"]) if isinstance(payload["assigned_to_id"], int) else None
        if not assignee or not assignee.is_active or assignee.role == "Viewer":
            return jsonify(success=False, error={"code": "INVALID_REQUEST", "message": "assigned_to_id must identify an active analyst or manager"}), 400
    try:
        update_incident(incident, payload, actor_id(), request_ip())
        db.session.commit()
    except ValueError as exc:
        db.session.rollback()
        return jsonify(success=False, error={"code": "INVALID_REQUEST", "message": str(exc)}), 400
    return jsonify(success=True, incident=incident.to_dict())
