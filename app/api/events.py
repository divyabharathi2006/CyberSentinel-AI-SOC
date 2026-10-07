from __future__ import annotations

from datetime import datetime
from math import ceil

from flask import jsonify, request
from flask_jwt_extended import jwt_required

from app import db
from app.api import api_bp
from app.models.event import Event
from app.services.audit_service import record_audit
from app.services.demo_data import generate_events
from app.services.kafka_pipeline import KafkaUnavailableError, is_kafka_enabled, publish_events
from app.services.log_ingestion import ingest_one, parse_upload
from app.services.log_normalizer import NormalizationError, normalize_event
from app.utils.security import actor_id, request_ip, roles_required


def _pagination():
    try:
        page = max(1, int(request.args.get("page", 1)))
        per_page = min(100, max(1, int(request.args.get("per_page", 50))))
    except ValueError:
        page, per_page = 1, 50
    return page, per_page


@api_bp.get("/events")
@jwt_required()
def list_events():
    query = Event.query
    filters = {
        "source_ip": Event.source_ip, "destination_ip": Event.destination_ip,
        "username": Event.username, "hostname": Event.hostname,
        "event_type": Event.event_type, "severity": Event.severity, "process": Event.process,
    }
    for key, column in filters.items():
        value = request.args.get(key)
        if value:
            query = query.filter(column.ilike(f"%{value.strip()}%"))
    search = request.args.get("q", "").strip()
    if search:
        pattern = f"%{search}%"
        query = query.filter(
            Event.source_ip.ilike(pattern)
            | Event.destination_ip.ilike(pattern)
            | Event.username.ilike(pattern)
            | Event.hostname.ilike(pattern)
            | Event.event_type.ilike(pattern)
            | Event.severity.ilike(pattern)
            | Event.process.ilike(pattern)
            | Event.message.ilike(pattern)
        )
    for name, operator in (("from", ">="), ("to", "<=")):
        value = request.args.get(name)
        if value:
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                return jsonify(success=False, error={"code": "INVALID_REQUEST", "message": f"{name} must be ISO-8601"}), 400
            query = query.filter(Event.timestamp >= parsed if operator == ">=" else Event.timestamp <= parsed)
    page, per_page = _pagination()
    pagination = query.order_by(Event.timestamp.desc()).paginate(page=page, per_page=per_page, error_out=False)
    return jsonify(success=True, items=[event.to_dict() for event in pagination.items], pagination={"page": page, "per_page": per_page, "total": pagination.total, "pages": ceil(pagination.total / per_page)})


@api_bp.get("/events/<int:event_id>")
@jwt_required()
def get_event(event_id: int):
    event = db.session.get(Event, event_id)
    if not event:
        return jsonify(success=False, error={"code": "NOT_FOUND", "message": "Event not found"}), 404
    return jsonify(success=True, event=event.to_dict())


@api_bp.post("/events")
@roles_required("Admin", "SOC Analyst", "Security Manager")
def create_event():
    payload = request.get_json(silent=True)
    if not isinstance(payload, (dict, list)):
        return jsonify(success=False, error={"code": "INVALID_REQUEST", "message": "A JSON event object or array is required"}), 400
    records = payload if isinstance(payload, list) else [payload]
    if not 1 <= len(records) <= 1000:
        return jsonify(success=False, error={"code": "INVALID_REQUEST", "message": "Submit between 1 and 1000 events"}), 400
    if is_kafka_enabled():
        validated, failures = [], []
        for index, record in enumerate(records):
            try:
                validated.append((normalize_event(record), "api"))
            except (NormalizationError, ValueError) as exc:
                failures.append({"index": index, "message": str(exc)})
        try:
            publish_events(validated, actor_id())
        except KafkaUnavailableError as exc:
            db.session.rollback()
            return jsonify(
                success=False,
                error={"code": "EVENT_QUEUE_UNAVAILABLE", "message": str(exc)},
            ), 503
        if validated:
            record_audit(
                "events_queued",
                "event_batch",
                None,
                actor_id(),
                request_ip(),
                {"queued": len(validated), "rejected": len(failures)},
            )
            db.session.commit()
        status = 202 if not failures else 207 if validated else 400
        return jsonify(
            success=not failures,
            accepted=len(validated),
            queued=len(validated),
            rejected=failures,
            events=[],
            alerts=[],
        ), status

    accepted, failures, alerts = [], [], []
    for index, record in enumerate(records):
        try:
            event, generated = ingest_one(record, actor_id())
            accepted.append(event.to_dict())
            alerts.extend(alert.to_dict() for alert in generated)
        except (NormalizationError, ValueError) as exc:
            db.session.rollback()
            failures.append({"index": index, "message": str(exc)})
    record_audit("events_ingested", "event_batch", None, actor_id(), request_ip(), {"accepted": len(accepted), "rejected": len(failures)})
    db.session.commit()
    status = 201 if not failures else 207 if accepted else 400
    return jsonify(success=not failures, accepted=len(accepted), rejected=failures, events=accepted, alerts=alerts), status


@api_bp.post("/demo/generate")
@roles_required("Admin", "SOC Analyst", "Security Manager")
def generate_demo_events():
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify(success=False, error={"code": "INVALID_REQUEST", "message": "A JSON object is required"}), 400
    count = payload.get("count", 80)
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= 900:
        return jsonify(success=False, error={"code": "INVALID_REQUEST", "message": "count must be an integer between 1 and 900"}), 400

    events = generate_events(count)
    if is_kafka_enabled():
        try:
            validated = [(normalize_event(record, default_source="synthetic-lab"), "synthetic-lab") for record in events]
            publish_events(validated, actor_id())
        except (NormalizationError, ValueError) as exc:
            return jsonify(success=False, error={"code": "INVALID_DEMO_EVENT", "message": str(exc)}), 500
        except KafkaUnavailableError as exc:
            return jsonify(
                success=False,
                error={"code": "EVENT_QUEUE_UNAVAILABLE", "message": str(exc)},
            ), 503
        record_audit(
            "demo_events_queued",
            "event_batch",
            None,
            actor_id(),
            request_ip(),
            {"queued": len(validated)},
        )
        db.session.commit()
        return jsonify(
            success=True,
            accepted=len(validated),
            queued=len(validated),
            rejected=[],
            alert_count=0,
            event_ids=[],
        ), 202

    accepted, rejected, alerts = [], [], []
    for index, record in enumerate(events):
        try:
            event, generated = ingest_one(record, actor_id(), default_source="synthetic-lab")
            accepted.append(event.id)
            alerts.extend(alert.id for alert in generated)
        except (NormalizationError, ValueError) as exc:
            db.session.rollback()
            rejected.append({"index": index, "message": str(exc)})
    record_audit(
        "demo_events_generated", "event_batch", None, actor_id(), request_ip(),
        {"accepted": len(accepted), "rejected": len(rejected)},
    )
    db.session.commit()
    status = 201 if not rejected else 207 if accepted else 400
    return jsonify(
        success=not rejected, accepted=len(accepted), rejected=rejected,
        alert_count=len(alerts), event_ids=accepted,
    ), status


@api_bp.post("/events/upload")
@roles_required("Admin", "SOC Analyst", "Security Manager")
def upload_events():
    if "file" not in request.files:
        return jsonify(success=False, error={"code": "INVALID_REQUEST", "message": "Upload a file using the 'file' field"}), 400
    uploaded = request.files["file"]
    if not uploaded.filename or "/" in uploaded.filename or "\\" in uploaded.filename:
        return jsonify(success=False, error={"code": "INVALID_REQUEST", "message": "A safe filename is required"}), 400
    try:
        records = parse_upload(uploaded.filename, uploaded.read())
    except (ValueError, UnicodeDecodeError, OSError) as exc:
        return jsonify(success=False, error={"code": "INVALID_FILE", "message": str(exc)}), 400
    if is_kafka_enabled():
        validated, rejected = [], []
        for index, record in enumerate(records):
            try:
                validated.append((normalize_event(record, default_source="file"), "file"))
            except (NormalizationError, ValueError) as exc:
                rejected.append({"index": index, "message": str(exc)})
        try:
            publish_events(validated, actor_id())
        except KafkaUnavailableError as exc:
            return jsonify(
                success=False,
                error={"code": "EVENT_QUEUE_UNAVAILABLE", "message": str(exc)},
            ), 503
        if validated:
            record_audit(
                "events_upload_queued",
                "event_batch",
                None,
                actor_id(),
                request_ip(),
                {"filename": uploaded.filename, "queued": len(validated), "rejected": len(rejected)},
            )
            db.session.commit()
        status = 202 if not rejected else 207 if validated else 400
        return jsonify(
            success=not rejected,
            accepted=len(validated),
            queued=len(validated),
            rejected=rejected,
            event_ids=[],
        ), status

    accepted, rejected = [], []
    for index, record in enumerate(records):
        try:
            event, _ = ingest_one(record, actor_id(), default_source="file")
            accepted.append(event.id)
        except (NormalizationError, ValueError) as exc:
            db.session.rollback()
            rejected.append({"index": index, "message": str(exc)})
    record_audit("events_uploaded", "event_batch", None, actor_id(), request_ip(), {"filename": uploaded.filename, "accepted": len(accepted), "rejected": len(rejected)})
    db.session.commit()
    status = 201 if not rejected else 207 if accepted else 400
    return jsonify(success=not rejected, accepted=len(accepted), rejected=rejected, event_ids=accepted), status
