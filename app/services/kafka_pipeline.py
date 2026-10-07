from __future__ import annotations

import json
import logging
from typing import Any

from flask import current_app

logger = logging.getLogger(__name__)


class KafkaUnavailableError(RuntimeError):
    pass


def _serialize_event(value: dict) -> bytes:
    return json.dumps(
        value, separators=(",", ":"), ensure_ascii=True, default=str
    ).encode("utf-8")


def is_kafka_enabled() -> bool:
    return bool(current_app.config["KAFKA_BOOTSTRAP_SERVERS"])


def _producer():
    producer = current_app.extensions.get("cybersentinel_kafka_producer")
    if producer is None:
        try:
            from kafka import KafkaProducer

            producer = KafkaProducer(
                bootstrap_servers=current_app.config["KAFKA_BOOTSTRAP_SERVERS"].split(","),
                acks="all",
                retries=5,
                max_in_flight_requests_per_connection=1,
                value_serializer=_serialize_event,
                request_timeout_ms=int(current_app.config["KAFKA_PUBLISH_TIMEOUT_SECONDS"] * 1000),
                max_block_ms=int(current_app.config["KAFKA_PUBLISH_TIMEOUT_SECONDS"] * 1000),
            )
        except Exception as exc:
            logger.exception("Could not initialize the Kafka event producer")
            raise KafkaUnavailableError("The real-time event queue is unavailable") from exc
        current_app.extensions["cybersentinel_kafka_producer"] = producer
    return producer


def publish_events(records: list[tuple[dict[str, Any], str]], actor_id: int | None) -> bool:
    if not is_kafka_enabled():
        return False
    if not records:
        return True

    producer = _producer()
    topic = current_app.config["KAFKA_EVENTS_TOPIC"]
    futures = []
    try:
        for event, source in records:
            futures.append(producer.send(topic, {
                "event": event,
                "actor_id": actor_id,
                "default_source": source,
            }))
        timeout = current_app.config["KAFKA_PUBLISH_TIMEOUT_SECONDS"]
        remaining = producer.flush(timeout=timeout)
        if remaining:
            raise TimeoutError("Kafka producer still has queued records after flush timeout")
        for future in futures:
            future.get(timeout=timeout)
    except Exception as exc:
        logger.exception("Could not publish event batch to Kafka")
        raise KafkaUnavailableError("The real-time event queue could not accept the event batch") from exc
    return True


def kafka_health() -> str:
    if not is_kafka_enabled():
        return "disabled"
    admin = None
    try:
        from kafka import KafkaAdminClient

        admin = KafkaAdminClient(
            bootstrap_servers=current_app.config["KAFKA_BOOTSTRAP_SERVERS"].split(","),
            request_timeout_ms=2000,
            api_version_auto_timeout_ms=2000,
            client_id="cybersentinel-health",
        )
        admin.describe_cluster()
        return "healthy"
    except Exception as exc:
        logger.warning("Kafka health check failed: %s", exc)
        return "unavailable"
    finally:
        if admin is not None:
            admin.close()


def worker_health() -> dict:
    from datetime import datetime, timezone

    from app.models.pipeline import KafkaWorkerStatus

    statuses = KafkaWorkerStatus.query.filter_by(
        topic=current_app.config["KAFKA_EVENTS_TOPIC"]
    ).all()
    now = datetime.now(timezone.utc)
    active = []
    for status in statuses:
        heartbeat = status.heartbeat_at
        if heartbeat.tzinfo is None:
            heartbeat = heartbeat.replace(tzinfo=timezone.utc)
        age_seconds = max(0, int((now - heartbeat).total_seconds()))
        active.append({
            "worker_id": status.worker_id,
            "state": "healthy" if age_seconds <= current_app.config["KAFKA_WORKER_HEARTBEAT_SECONDS"] * 3 else "stale",
            "heartbeat_age_seconds": age_seconds,
            "consumer_lag": status.consumer_lag,
            "events_processed": status.events_processed,
            "messages_dead_lettered": status.messages_dead_lettered,
            "last_error": status.last_error,
        })
    threshold = current_app.config["KAFKA_MAX_HEALTHY_LAG"]
    healthy_workers = [
        worker for worker in active
        if worker["state"] == "healthy" and worker["consumer_lag"] <= threshold
    ]
    return {
        "state": "healthy" if healthy_workers else "unavailable",
        "topic": current_app.config["KAFKA_EVENTS_TOPIC"],
        "consumer_group": current_app.config["KAFKA_CONSUMER_GROUP"],
        "dead_letter_topic": current_app.config["KAFKA_DEAD_LETTER_TOPIC"],
        "max_healthy_lag": threshold,
        "workers": active,
    }
