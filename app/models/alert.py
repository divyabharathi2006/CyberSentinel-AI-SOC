from __future__ import annotations

from datetime import datetime, timezone

from app import db
from app.options import ALERT_STATUS_OPTIONS

ALERT_STATUSES = frozenset(ALERT_STATUS_OPTIONS)


class Alert(db.Model):
    __tablename__ = "alerts"
    __table_args__ = (
        db.Index("ix_alerts_status_severity", "status", "severity"),
        db.Index("ix_alerts_created", "created_at"),
        db.UniqueConstraint("fingerprint", name="uq_alert_fingerprint"),
    )

    id = db.Column(db.Integer, primary_key=True)
    fingerprint = db.Column(db.String(64), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.String(2000), nullable=False)
    rule_id = db.Column(db.String(80), nullable=False)
    rule_name = db.Column(db.String(160), nullable=False)
    severity = db.Column(db.String(20), nullable=False, index=True)
    risk_score = db.Column(db.Integer, nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(24), nullable=False, default="NEW", index=True)
    source_ip = db.Column(db.String(45), index=True)
    destination_ip = db.Column(db.String(45), index=True)
    username = db.Column(db.String(128), index=True)
    detection_source = db.Column(db.String(40), nullable=False, default="rule")
    anomaly_score = db.Column(db.Float)
    model_version = db.Column(db.String(40))
    evidence = db.Column(db.JSON, nullable=False, default=list)
    ml_feature_summary = db.Column(db.JSON, nullable=False, default=dict)
    score_breakdown = db.Column(db.JSON, nullable=False, default=dict)
    mitre = db.Column(db.JSON, nullable=False, default=list)
    recommended_action = db.Column(db.String(1000), nullable=False)
    analyst_notes = db.Column(db.JSON, nullable=False, default=list)
    assigned_to_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    resolved_at = db.Column(db.DateTime(timezone=True))
    assigned_to = db.relationship("User")
    event_links = db.relationship("AlertEvent", cascade="all, delete-orphan", back_populates="alert")

    def to_dict(self) -> dict:
        return {
            "id": self.id, "title": self.title, "description": self.description,
            "rule_id": self.rule_id, "rule_name": self.rule_name, "severity": self.severity,
            "risk_score": self.risk_score, "confidence": self.confidence, "status": self.status,
            "source_ip": self.source_ip, "destination_ip": self.destination_ip, "username": self.username,
            "detection_source": self.detection_source, "anomaly_score": self.anomaly_score,
            "model_version": self.model_version, "evidence": self.evidence or [],
            "ml_feature_summary": self.ml_feature_summary or {},
            "score_breakdown": self.score_breakdown or {}, "mitre": self.mitre or [],
            "recommended_action": self.recommended_action, "analyst_notes": self.analyst_notes or [],
            "assigned_to": self.assigned_to.to_dict() if self.assigned_to else None,
            "event_ids": [link.event_id for link in self.event_links],
            "created_at": self.created_at.isoformat(), "updated_at": self.updated_at.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
        }


class AlertEvent(db.Model):
    __tablename__ = "alert_events"
    alert_id = db.Column(db.Integer, db.ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey("events.id", ondelete="CASCADE"), primary_key=True)
    alert = db.relationship("Alert", back_populates="event_links")
    event = db.relationship("Event")
