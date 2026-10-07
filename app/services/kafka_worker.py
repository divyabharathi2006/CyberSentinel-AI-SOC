from __future__ import annotations

import json
import logging
import platform
import time
from datetime import datetime, timezone

from flask import Flask
from kafka import KafkaConsumer, KafkaProducer
from kafka.structs import OffsetAndMetadata, TopicPartition

from app import db
from app.models.pipeline import KafkaPartitionCheckpoint, KafkaWorkerStatus
from app.services.log_ingestion import ingest_one, publish_ingested
from app.services.log_normalizer import NormalizationError

logger = logging.getLogger(__name__)


class EventWorker:
    def __init__(self, app: Flask):
        self.app = app
        self.worker_id = app.config["KAFKA_WORKER_ID"] or platform.node()
        self.topic = app.config["KAFKA_EVENTS_TOPIC"]
        servers = app.config["KAFKA_BOOTSTRAP_SERVERS"].split(",")
        self.consumer = KafkaConsumer(
            bootstrap_servers=servers,
            group_id=app.config["KAFKA_CONSUMER_GROUP"],
            enable_auto_commit=False,
            auto_offset_reset="earliest",
            max_poll_records=1,
            consumer_timeout_ms=1000,
            request_timeout_ms=30000,
            max_poll_interval_ms=300000,
        )
        self.consumer.subscribe([self.topic])
        self.dead_letter_producer = KafkaProducer(
            bootstrap_servers=servers,
            acks="all",
            retries=5,
            value_serializer=lambda value: json.dumps(
                value, separators=(",", ":"), ensure_ascii=True, default=str
            ).encode("utf-8"),
            request_timeout_ms=10000,
        )

    def run(self) -> None:
        with self.app.app_context():
            db.create_all()
            self._heartbeat(consumer_lag=0)
        next_heartbeat = 0.0
        while True:
            try:
                records = self.consumer.poll(timeout_ms=1000, max_records=1)
                for messages in records.values():
                    for message in messages:
                        self._handle(message)
                now = time.monotonic()
                if now >= next_heartbeat:
                    self._heartbeat(consumer_lag=self._consumer_lag())
                    next_heartbeat = now + self.app.config["KAFKA_WORKER_HEARTBEAT_SECONDS"]
            except KeyboardInterrupt:
                return
            except Exception:
                logger.exception("Kafka event worker loop failed; retrying")
                time.sleep(2)

    def close(self) -> None:
        self.consumer.close()
        self.dead_letter_producer.close()

    def _handle(self, message) -> None:
        checkpoint_key = (message.topic, message.partition)
        with self.app.app_context():
            try:
                checkpoint = db.session.get(KafkaPartitionCheckpoint, checkpoint_key)
                if checkpoint and message.offset <= checkpoint.last_offset:
                    self._commit_offset(message)
                    return
                envelope = json.loads(message.value.decode("utf-8"))
                if not isinstance(envelope, dict):
                    raise NormalizationError("Kafka message must contain a JSON object")
                if "event" in envelope:
                    event_payload = envelope["event"]
                    source = envelope.get("default_source", "kafka")
                else:
                    event_payload = envelope
                    source = "kafka"
                if not isinstance(event_payload, dict) or not isinstance(source, str):
                    raise NormalizationError("Kafka event envelope is invalid")
                event, alerts = ingest_one(
                    event_payload,
                    actor_id=None,
                    default_source=source,
                    commit=False,
                )
                self._advance_checkpoint(message)
                self._increment_status("events_processed")
                db.session.commit()
                self._commit_offset(message)
                publish_ingested(event, alerts)
            except (UnicodeDecodeError, json.JSONDecodeError, NormalizationError, ValueError) as exc:
                db.session.rollback()
                try:
                    self._dead_letter(message, str(exc))
                except Exception:
                    db.session.rollback()
                    self._seek_for_retry(message)
                    raise
            except Exception:
                db.session.rollback()
                self._seek_for_retry(message)
                logger.exception(
                    "Processing Kafka record failed at %s[%s] offset %s",
                    message.topic,
                    message.partition,
                    message.offset,
                )
                raise

    def _advance_checkpoint(self, message) -> None:
        key = (message.topic, message.partition)
        checkpoint = db.session.get(KafkaPartitionCheckpoint, key)
        if checkpoint is None:
            checkpoint = KafkaPartitionCheckpoint(
                topic=message.topic,
                partition=message.partition,
                last_offset=message.offset,
            )
            db.session.add(checkpoint)
        else:
            checkpoint.last_offset = message.offset
            checkpoint.processed_at = datetime.now(timezone.utc)

    def _dead_letter(self, message, reason: str) -> None:
        raw = message.value.decode("utf-8", errors="replace")
        self.dead_letter_producer.send(
            self.app.config["KAFKA_DEAD_LETTER_TOPIC"],
            {
                "source_topic": message.topic,
                "source_partition": message.partition,
                "source_offset": message.offset,
                "failed_at": datetime.now(timezone.utc).isoformat(),
                "reason": reason[:1000],
                "raw_message": raw[:100000],
            },
        ).get(timeout=10)
        self._advance_checkpoint(message)
        self._increment_status("messages_dead_lettered", error=reason[:500])
        db.session.commit()
        self._commit_offset(message)
        logger.warning(
            "Moved invalid Kafka record to dead-letter topic from %s[%s] offset %s: %s",
            message.topic,
            message.partition,
            message.offset,
            reason,
        )

    def _increment_status(self, counter: str, error: str | None = None) -> None:
        status = db.session.get(KafkaWorkerStatus, self.worker_id)
        if status is None:
            status = KafkaWorkerStatus(
                worker_id=self.worker_id,
                topic=self.topic,
                consumer_lag=0,
                events_processed=0,
                messages_dead_lettered=0,
            )
            db.session.add(status)
        setattr(status, counter, getattr(status, counter) + 1)
        status.heartbeat_at = datetime.now(timezone.utc)
        status.last_error = error

    def _heartbeat(self, consumer_lag: int) -> None:
        with self.app.app_context():
            status = db.session.get(KafkaWorkerStatus, self.worker_id)
            if status is None:
                status = KafkaWorkerStatus(
                    worker_id=self.worker_id,
                    topic=self.topic,
                    consumer_lag=0,
                    events_processed=0,
                    messages_dead_lettered=0,
                )
                db.session.add(status)
            status.heartbeat_at = datetime.now(timezone.utc)
            status.consumer_lag = max(0, consumer_lag)
            db.session.commit()

    def _consumer_lag(self) -> int:
        partitions = self.consumer.assignment()
        if not partitions:
            return 0
        end_offsets = self.consumer.end_offsets(partitions)
        lag = 0
        for partition in partitions:
            position = self.consumer.position(partition)
            if position is not None:
                lag += max(0, end_offsets.get(partition, position) - position)
        return lag

    def _commit_offset(self, message) -> None:
        partition = TopicPartition(message.topic, message.partition)
        metadata = OffsetAndMetadata(message.offset + 1, "")
        self.consumer.commit({partition: metadata})

    def _seek_for_retry(self, message) -> None:
        self.consumer.seek(TopicPartition(message.topic, message.partition), message.offset)
