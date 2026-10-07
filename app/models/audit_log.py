from datetime import datetime, timezone

from app import db


class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    __table_args__ = (db.Index("ix_audit_actor_time", "actor_id", "created_at"),)

    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    action = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(80), nullable=False)
    resource_id = db.Column(db.String(100))
    ip_address = db.Column(db.String(45))
    details = db.Column(db.JSON, nullable=False, default=dict)
    previous_hash = db.Column(db.String(64))
    entry_hash = db.Column(db.String(64), nullable=False, unique=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    actor = db.relationship("User")
