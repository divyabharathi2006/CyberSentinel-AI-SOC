from datetime import datetime, timezone

from app import db


class ModelVersion(db.Model):
    __tablename__ = "model_versions"

    id = db.Column(db.Integer, primary_key=True)
    version = db.Column(db.String(40), unique=True, nullable=False)
    algorithm = db.Column(db.String(80), nullable=False)
    dataset_version = db.Column(db.String(80), nullable=False)
    feature_version = db.Column(db.String(40), nullable=False)
    metrics = db.Column(db.JSON, nullable=False, default=dict)
    artifact_path = db.Column(db.String(500), nullable=False)
    trained_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
