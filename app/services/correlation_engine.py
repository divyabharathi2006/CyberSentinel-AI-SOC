from __future__ import annotations

from datetime import timedelta

from flask import current_app

from app.models.event import Event


def correlate_event(event: Event) -> dict | None:
    event_type = event.event_type.lower()
    auth_related = any(term in event_type for term in ("auth", "login", "authentication"))
    if not auth_related or not event.source_ip:
        return None

    failed = event.status and event.status.lower() in {"failed", "failure", "denied", "invalid"}
    succeeded = event.status and event.status.lower() in {"success", "succeeded", "accepted", "ok"}
    if not (failed or succeeded):
        return None

    start = event.timestamp - timedelta(minutes=current_app.config["AUTH_CORRELATION_WINDOW_MINUTES"])
    related_query = Event.query.filter(
        Event.timestamp >= start,
        Event.timestamp <= event.timestamp,
        Event.source_ip == event.source_ip,
        Event.id != event.id,
    )
    if event.username:
        related_query = related_query.filter(Event.username == event.username)
    related = related_query.order_by(Event.timestamp.asc()).all()
    failures = [e for e in related if e.status and e.status.lower() in {"failed", "failure", "denied", "invalid"}]
    if succeeded and len(failures) >= 3:
        evidence = failures + [event]
        return {
            "rule_id": "AUTH-001-CORRELATED",
            "rule_name": "Repeated failures followed by successful authentication",
            "title": "Potential account access after repeated authentication failures",
            "description": f"A successful authentication followed {len(failures)} failed attempts from the same source within {current_app.config['AUTH_CORRELATION_WINDOW_MINUTES']} minutes. This pattern warrants investigation and is not proof of compromise.",
            "severity": "high",
            "confidence": 0.82,
            "event_ids": [e.id for e in evidence],
            "frequency": len(evidence),
            "mitre": [{"id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "reason": "Repeated failed authentications were followed by a success."}],
            "recommended_action": "Verify the successful sign-in with the account owner; review MFA and related session activity.",
        }
    return None
