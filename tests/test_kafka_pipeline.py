from __future__ import annotations

import json
import sqlite3
from types import SimpleNamespace

from app import db
from app.models.event import Event
from app.models.pipeline import KafkaPartitionCheckpoint
from app.models.user import User
from app.services import kafka_pipeline
from app.services.kafka_worker import EventWorker
from scripts.reset_database import _backup_database, _clear_database


class _Future:
    def get(self, timeout=None):
        return None


class _Producer:
    def __init__(self):
        self.messages = []

    def send(self, topic, value):
        self.messages.append((topic, value))
        return _Future()

    def flush(self, timeout=None):
        return 0


class _Consumer:
    def __init__(self):
        self.commits = []
        self.seeks = []

    def commit(self, offsets):
        self.commits.append(offsets)

    def seek(self, partition, offset):
        self.seeks.append((partition, offset))


def test_events_are_acknowledged_by_kafka_before_processing(client, analyst_headers, app):
    producer = _Producer()
    app.config["KAFKA_BOOTSTRAP_SERVERS"] = "broker:9092"
    app.extensions["cybersentinel_kafka_producer"] = producer
    event = {
        "event_type": "authentication",
        "source_ip": "198.51.100.17",
        "username": "soc-test",
        "status": "failed",
        "severity": "medium",
        "message": "Synthetic test event",
    }

    response = client.post("/api/events", headers=analyst_headers, json=event)

    assert response.status_code == 202
    assert response.json["accepted"] == response.json["queued"] == 1
    assert producer.messages[0][0] == "cybersentinel.events"
    assert producer.messages[0][1]["event"]["event_type"] == "authentication"
    serialized = kafka_pipeline._serialize_event(producer.messages[0][1])
    assert json.loads(serialized.decode())["event"]["timestamp"].startswith("20")
    with app.app_context():
        assert Event.query.count() == 0


def test_worker_persists_once_when_a_kafka_offset_is_replayed(app):
    worker = object.__new__(EventWorker)
    worker.app = app
    worker.worker_id = "test-worker"
    worker.topic = "cybersentinel.events"
    worker.consumer = _Consumer()
    worker.dead_letter_producer = _Producer()
    message = SimpleNamespace(
        topic="cybersentinel.events",
        partition=0,
        offset=4,
        value=json.dumps({
            "event": {
                "event_type": "authentication",
                "source_ip": "198.51.100.22",
                "username": "worker-test",
                "status": "failed",
                "severity": "medium",
                "message": "Synthetic worker test",
            },
            "default_source": "api",
        }).encode(),
    )

    worker._handle(message)
    worker._handle(message)

    with app.app_context():
        assert Event.query.count() == 1
        checkpoint = db.session.get(KafkaPartitionCheckpoint, ("cybersentinel.events", 0))
        assert checkpoint.last_offset == 4
        db.session.remove()
    assert len(worker.consumer.commits) == 2
    assert worker.consumer.seeks == []


def test_worker_dead_letters_invalid_records(app):
    worker = object.__new__(EventWorker)
    worker.app = app
    worker.worker_id = "test-worker"
    worker.topic = "cybersentinel.events"
    worker.consumer = _Consumer()
    worker.dead_letter_producer = _Producer()
    message = SimpleNamespace(
        topic="cybersentinel.events",
        partition=1,
        offset=2,
        value=b'{"event": []}',
    )

    worker._handle(message)

    assert worker.dead_letter_producer.messages[0][0] == "cybersentinel.events.dlq"
    assert worker.dead_letter_producer.messages[0][1]["source_offset"] == 2
    assert len(worker.consumer.commits) == 1
    assert worker.consumer.seeks == []


def test_database_reset_backs_up_before_clearing_and_preserves_users(app, tmp_path):
    with app.app_context():
        db.session.add(Event(event_type="test", severity="informational", source="test"))
        db.session.commit()
        backup = _backup_database(
            app.config["SQLALCHEMY_DATABASE_URI"],
            tmp_path / "database-backups",
        )
        second_backup = _backup_database(
            app.config["SQLALCHEMY_DATABASE_URI"],
            tmp_path / "database-backups",
        )
        deleted = _clear_database(include_users=False, include_audit=False)

        assert backup.is_file()
        assert second_backup.is_file()
        assert second_backup != backup
        assert "events" in deleted
        assert Event.query.count() == 0
        assert User.query.count() == 4
        with sqlite3.connect(backup) as snapshot:
            assert snapshot.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
