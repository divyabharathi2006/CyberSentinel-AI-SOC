from __future__ import annotations

from datetime import datetime, timezone

from app import db
from app.options import INCIDENT_STATUS_OPTIONS

INCIDENT_STATUSES = frozenset(INCIDENT_STATUS_OPTIONS)


class IncidentAlert(db.Model):
    __tablename__ = "incident_alerts"
    incident_id = db.Column(db.Integer, db.ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True)
    alert_id = db.Column(db.Integer, db.ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True)
    alert = db.relationship("Alert")


class Incident(db.Model):
    __tablename__ = "incidents"
    __table_args__ = (db.Index("ix_incidents_status_severity", "status", "severity"),)

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.String(4000), nullable=False)
    severity = db.Column(db.String(20), nullable=False, default="medium")
    status = db.Column(db.String(24), nullable=False, default="Open", index=True)
    assigned_to_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    notes = db.Column(db.JSON, nullable=False, default=list)
    timeline = db.Column(db.JSON, nullable=False, default=list)
    resolution = db.Column(db.String(2000))
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    assigned_to = db.relationship("User")
    alert_links = db.relationship("IncidentAlert", cascade="all, delete-orphan")

    def to_dict(self) -> dict:
        return {
            "id": self.id, "title": self.title, "description": self.description,
            "severity": self.severity, "status": self.status,
            "assigned_to": self.assigned_to.to_dict() if self.assigned_to else None,
            "alert_ids": [link.alert_id for link in self.alert_links],
            "notes": self.notes or [], "timeline": self.timeline or [],
            "resolution": self.resolution, "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
