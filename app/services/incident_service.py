from __future__ import annotations

from datetime import datetime, timezone

from app import db
from app.models.alert import Alert
from app.models.incident import INCIDENT_STATUSES, Incident, IncidentAlert
from app.options import SEVERITY_OPTIONS
from app.services.audit_service import record_audit


def create_incident(title: str, description: str, severity: str, alert_ids: list[int], actor_id: int | None, ip_address: str | None) -> Incident:
    if not title.strip() or len(title) > 200:
        raise ValueError("title must contain 1 to 200 characters")
    if not description.strip() or len(description) > 4000:
        raise ValueError("description must contain 1 to 4000 characters")
    if severity not in SEVERITY_OPTIONS:
        raise ValueError("severity is invalid")
    alerts = Alert.query.filter(Alert.id.in_(alert_ids)).all() if alert_ids else []
    if len(alerts) != len(set(alert_ids)):
        raise ValueError("One or more alert IDs do not exist")
    now = datetime.now(timezone.utc)
    incident = Incident(
        title=title.strip(), description=description.strip(), severity=severity,
        status="Open", notes=[], timeline=[{"action": "created", "actor_id": actor_id, "at": now.isoformat()}],
    )
    db.session.add(incident)
    db.session.flush()
    for alert in alerts:
        db.session.add(IncidentAlert(incident_id=incident.id, alert_id=alert.id))
    record_audit("incident_created", "incident", incident.id, actor_id, ip_address, {"alert_ids": alert_ids})
    return incident


def update_incident(incident: Incident, payload: dict, actor_id: int | None, ip_address: str | None) -> None:
    changed = []
    if "status" in payload:
        status = payload["status"]
        if not isinstance(status, str) or status not in INCIDENT_STATUSES:
            raise ValueError(f"status must be one of {sorted(INCIDENT_STATUSES)}")
        incident.status = status
        changed.append("status")
    if "resolution" in payload:
        value = payload["resolution"]
        if not isinstance(value, str) or len(value) > 2000:
            raise ValueError("resolution must be at most 2000 characters")
        incident.resolution = value.strip()
        changed.append("resolution")
    if "assigned_to_id" in payload:
        incident.assigned_to_id = payload["assigned_to_id"]
        changed.append("assigned_to_id")
    if "note" in payload:
        note = payload["note"]
        if not isinstance(note, str) or not note.strip() or len(note) > 2000:
            raise ValueError("note must contain 1 to 2000 characters")
        notes = list(incident.notes or [])
        notes.append({"user_id": actor_id, "note": note.strip(), "created_at": datetime.now(timezone.utc).isoformat()})
        incident.notes = notes[-100:]
        changed.append("note")
    now = datetime.now(timezone.utc).isoformat()
    timeline = list(incident.timeline or [])
    timeline.append({"action": "updated", "fields": changed, "actor_id": actor_id, "at": now})
    incident.timeline = timeline[-200:]
    record_audit("incident_updated", "incident", incident.id, actor_id, ip_address, {"changed_fields": changed})
