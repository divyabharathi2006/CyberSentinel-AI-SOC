from datetime import timedelta

from flask import current_app

from app.models.event import Event


def destination_port_fanout_rule(event: Event) -> dict | None:
    if not event.source_ip or not event.destination_port:
        return None
    if not any(word in event.event_type.lower() for word in ("network", "connection", "firewall", "flow")):
        return None
    events = Event.query.filter(
        Event.source_ip == event.source_ip,
        Event.timestamp >= event.timestamp - timedelta(minutes=current_app.config["NETWORK_WINDOW_MINUTES"]),
        Event.timestamp <= event.timestamp,
        Event.destination_port.isnot(None),
    ).all()
    ports = sorted({item.destination_port for item in events})
    if len(ports) < current_app.config["NETWORK_PORT_THRESHOLD"]:
        return None
    return {
        "rule_id": "NET-001",
        "rule_name": "Unusual destination-port fan-out",
        "title": "Unusual network connection fan-out observed",
        "description": f"The source contacted {len(ports)} distinct destination ports within {current_app.config['NETWORK_WINDOW_MINUTES']} minutes. Validate this against authorized scanning or asset discovery activity.",
        "severity": "medium",
        "confidence": 0.65,
        "event_ids": [item.id for item in events],
        "frequency": len(events),
        "mitre": [{"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery", "reason": "A high number of destination ports were observed in a short interval."}],
        "recommended_action": "Check asset inventory, approved scanner schedules, and firewall telemetry before escalation.",
    }
