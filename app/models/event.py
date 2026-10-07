from __future__ import annotations

from datetime import datetime, timezone

from app import db


class Event(db.Model):
    __tablename__ = "events"
    __table_args__ = (
        db.Index("ix_events_created_severity", "timestamp", "severity"),
        db.Index("ix_events_src_time", "source_ip", "timestamp"),
        db.Index("ix_events_user_time", "username", "timestamp"),
    )

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    received_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    source_ip = db.Column(db.String(45), index=True)
    destination_ip = db.Column(db.String(45), index=True)
    source_port = db.Column(db.Integer)
    destination_port = db.Column(db.Integer)
    protocol = db.Column(db.String(16))
    username = db.Column(db.String(128), index=True)
    hostname = db.Column(db.String(255), index=True)
    event_type = db.Column(db.String(80), nullable=False, index=True)
    action = db.Column(db.String(80))
    status = db.Column(db.String(40))
    process = db.Column(db.String(255))
    message = db.Column(db.String(2000))
    severity = db.Column(db.String(20), nullable=False, default="informational", index=True)
    source = db.Column(db.String(80), nullable=False, default="api")
    metadata_json = db.Column(db.JSON, nullable=False, default=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "received_at": self.received_at.isoformat(),
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "username": self.username,
            "hostname": self.hostname,
            "event_type": self.event_type,
            "action": self.action,
            "status": self.status,
            "process": self.process,
            "message": self.message,
            "severity": self.severity,
            "source": self.source,
            "metadata": self.metadata_json or {},
        }
