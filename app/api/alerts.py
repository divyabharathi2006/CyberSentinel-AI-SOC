from __future__ import annotations

from datetime import datetime, timezone
from math import ceil

from flask import jsonify, request
from flask_jwt_extended import jwt_required

from app import db
from app.api import api_bp
from app.models.alert import ALERT_STATUSES, Alert
from app.models.user import User
from app.services.audit_service import record_audit
from app.utils.security import actor_id, request_ip, roles_required


@api_bp.get("/alerts")
@jwt_required()
def list_alerts():
    query = Alert.query
    status = request.args.get("status")
    severity = request.args.get("severity", "").lower()
    if status:
        query = query.filter_by(status=status.upper())
    if severity:
        query = query.filter_by(severity=severity)
    page = max(1, request.args.get("page", 1, type=int))
    per_page = min(100, max(1, request.args.get("per_page", 50, type=int)))
    pagination = query.order_by(Alert.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    return jsonify(success=True, items=[alert.to_dict() for alert in pagination.items], pagination={"page": page, "per_page": per_page, "total": pagination.total, "pages": ceil(pagination.total / per_page)})


@api_bp.get("/alerts/<int:alert_id>")
@jwt_required()
def get_alert(alert_id: int):
    alert = db.session.get(Alert, alert_id)
    if not alert:
        return jsonify(success=False, error={"code": "NOT_FOUND", "message": "Alert not found"}), 404
    record_audit("alert_viewed", "alert", alert.id, actor_id(), request_ip())
    db.session.commit()
    from flask import current_app

    from app.services.threat_intel import lookup_indicator

    enrichment = lookup_indicator(alert.source_ip, current_app.config["THREAT_INTEL_API_KEY"]) if alert.source_ip else None
    return jsonify(success=True, alert=alert.to_dict(), events=[link.event.to_dict() for link in alert.event_links], threat_intelligence=enrichment)


@api_bp.patch("/alerts/<int:alert_id>")
@roles_required("Admin", "SOC Analyst", "Security Manager")
def update_alert(alert_id: int):
    alert = db.session.get(Alert, alert_id)
    if not alert:
        return jsonify(success=False, error={"code": "NOT_FOUND", "message": "Alert not found"}), 404
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(success=False, error={"code": "INVALID_REQUEST", "message": "A JSON object is required"}), 400
    if "status" in payload:
        status = payload["status"]
        if not isinstance(status, str) or status.upper() not in ALERT_STATUSES:
            return jsonify(success=False, error={"code": "INVALID_REQUEST", "message": f"status must be one of {sorted(ALERT_STATUSES)}"}), 400
        alert.status = status.upper()
        if alert.status == "RESOLVED":
            alert.resolved_at = datetime.now(timezone.utc)
    if "assigned_to_id" in payload:
        assignee = db.session.get(User, payload["assigned_to_id"]) if payload["assigned_to_id"] is not None else None
        if payload["assigned_to_id"] is not None and (not assignee or not assignee.is_active or assignee.role == "Viewer"):
            return jsonify(success=False, error={"code": "INVALID_REQUEST", "message": "assigned_to_id must identify an active analyst or manager"}), 400
        alert.assigned_to = assignee
    if "note" in payload:
        note = payload["note"]
        if not isinstance(note, str) or not note.strip() or len(note) > 2000:
            return jsonify(success=False, error={"code": "INVALID_REQUEST", "message": "note must contain 1 to 2000 characters"}), 400
        notes = list(alert.analyst_notes or [])
        notes.append({"user_id": actor_id(), "note": note.strip(), "created_at": datetime.now(timezone.utc).isoformat()})
        alert.analyst_notes = notes[-100:]
    record_audit("alert_updated", "alert", alert.id, actor_id(), request_ip(), {"changed_fields": sorted(payload.keys())})
    db.session.commit()
    return jsonify(success=True, alert=alert.to_dict())


@api_bp.post("/alerts/<int:alert_id>/incidents")
@roles_required("Admin", "SOC Analyst", "Security Manager")
def create_incident_from_alert(alert_id: int):
    from app.services.incident_service import create_incident

    alert = db.session.get(Alert, alert_id)
    if not alert:
        return jsonify(success=False, error={"code": "NOT_FOUND", "message": "Alert not found"}), 404
    incident = create_incident(
        title=f"Investigation: {alert.title}",
        description=alert.description,
        severity=alert.severity,
        alert_ids=[alert.id],
        actor_id=actor_id(),
        ip_address=request_ip(),
    )
    db.session.commit()
    return jsonify(success=True, incident=incident.to_dict()), 201
