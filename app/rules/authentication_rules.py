from datetime import timedelta

from flask import current_app

from app.models.event import Event


def failed_authentication_rule(event: Event) -> dict | None:
    if not any(term in event.event_type.lower() for term in ("auth", "login", "authentication")):
        return None
    if not event.status or event.status.lower() not in {"failed", "failure", "denied", "invalid"}:
        return None
    if not event.source_ip:
        return None
    matching = Event.query.filter(
        Event.source_ip == event.source_ip,
        Event.timestamp >= event.timestamp - timedelta(minutes=current_app.config["AUTH_WINDOW_MINUTES"]),
        Event.timestamp <= event.timestamp,
        Event.event_type.ilike("%auth%") | Event.event_type.ilike("%login%"),
        Event.status.in_(("failed", "failure", "denied", "invalid")),
    )
    if event.username:
        matching = matching.filter(Event.username == event.username)
    events = matching.order_by(Event.timestamp.asc()).all()
    if len(events) < 5:
        return None
    return {
        "rule_id": "AUTH-001",
        "rule_name": "Repeated failed authentication",
        "title": "Potential brute-force behavior detected",
        "description": f"{len(events)} failed authentication events for this source/account were observed within {current_app.config['AUTH_WINDOW_MINUTES']} minutes.",
        "severity": "high",
        "confidence": 0.78,
        "event_ids": [item.id for item in events],
        "frequency": len(events),
        "mitre": [{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "reason": "Repeated failed authentications from the same source."}],
        "recommended_action": "Review source reputation and authentication context; confirm account activity with its owner.",
    }
