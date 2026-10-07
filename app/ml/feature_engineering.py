from __future__ import annotations

from datetime import datetime
from typing import Any

FEATURE_NAMES = [
    "hour_utc", "is_weekend", "source_port", "destination_port",
    "auth_failure", "auth_success", "network_event", "privilege_event",
    "high_severity", "message_length",
]
FEATURE_VERSION = "1"


def event_features(event: dict[str, Any]) -> list[float]:
    timestamp = event.get("timestamp")
    if isinstance(timestamp, str):
        try:
            timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            timestamp = None
    timestamp = timestamp or datetime.utcnow()
    event_type = str(event.get("event_type", "")).lower()
    status = str(event.get("status", "")).lower()
    action = str(event.get("action", "")).lower()
    text = f"{event_type} {action} {status}".lower()
    failed = any(value in text for value in ("fail", "denied", "invalid"))
    success = "success" in text or status in {"accepted", "ok"}
    network = any(value in text for value in ("network", "connection", "firewall", "dns"))
    privilege = any(value in text for value in ("privilege", "role", "sudo", "admin"))
    severity = str(event.get("severity", "informational")).lower()
    message_length = min(len(str(event.get("message", ""))), 2000)
    return [
        float(timestamp.hour),
        float(timestamp.weekday() >= 5),
        float(event.get("source_port") or 0),
        float(event.get("destination_port") or 0),
        float(failed),
        float(success),
        float(network),
        float(privilege),
        float(severity in {"high", "critical"}),
        float(message_length),
    ]
