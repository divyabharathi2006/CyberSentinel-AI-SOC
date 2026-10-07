from __future__ import annotations

from datetime import datetime, timezone

from app import db


class KafkaPartitionCheckpoint(db.Model):
    __tablename__ = "kafka_partition_checkpoints"

    topic = db.Column(db.String(249), primary_key=True)
    partition = db.Column(db.Integer, primary_key=True)
    last_offset = db.Column(db.BigInteger, nullable=False)
    processed_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class KafkaWorkerStatus(db.Model):
    __tablename__ = "kafka_worker_status"

    worker_id = db.Column(db.String(255), primary_key=True)
    topic = db.Column(db.String(249), nullable=False)
    heartbeat_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    consumer_lag = db.Column(db.BigInteger, nullable=False, default=0)
    events_processed = db.Column(db.BigInteger, nullable=False, default=0)
    messages_dead_lettered = db.Column(db.BigInteger, nullable=False, default=0)
    last_error = db.Column(db.String(500))
