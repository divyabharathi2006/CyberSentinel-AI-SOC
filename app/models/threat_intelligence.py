from datetime import datetime, timezone

from app import db


class ThreatIntelligence(db.Model):
    __tablename__ = "threat_intelligence"
    __table_args__ = (db.UniqueConstraint("indicator_type", "indicator", name="uq_threat_indicator"),)

    id = db.Column(db.Integer, primary_key=True)
    indicator_type = db.Column(db.String(16), nullable=False, index=True)
    indicator = db.Column(db.String(512), nullable=False, index=True)
    reputation = db.Column(db.String(32), nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    source = db.Column(db.String(80), nullable=False)
    first_seen = db.Column(db.DateTime(timezone=True))
    last_seen = db.Column(db.DateTime(timezone=True))
    tags = db.Column(db.JSON, nullable=False, default=list)
    raw_summary = db.Column(db.JSON, nullable=False, default=dict)
    checked_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
