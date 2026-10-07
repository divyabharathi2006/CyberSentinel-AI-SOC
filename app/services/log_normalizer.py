from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any

from app.options import SEVERITY_OPTIONS
from app.utils.validators import validate_event_shape

SEVERITIES = frozenset(SEVERITY_OPTIONS)
_SYSLOG = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s[\d:]+)\s+(?P<host>\S+)\s+(?P<process>[^:\[]+)(?:\[\d+\])?:\s*(?P<message>.*)$"
)
_ALIASES = {
    "src_ip": "source_ip", "src": "source_ip", "client_ip": "source_ip",
    "dst_ip": "destination_ip", "dst": "destination_ip", "remote_ip": "destination_ip",
    "user": "username", "account": "username", "type": "event_type", "event": "event_type",
    "host": "hostname", "app": "source", "severity_text": "severity",
}


class NormalizationError(ValueError):
    pass


def _clean_text(value: Any, name: str, limit: int) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, (str, int, float)):
        raise NormalizationError(f"{name} must be a string or number")
    result = str(value).strip()
    if len(result) > limit:
        raise NormalizationError(f"{name} exceeds {limit} characters")
    return result or None


def _ip(value: Any, name: str) -> str | None:
    text = _clean_text(value, name, 45)
    if text is None:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError as exc:
        raise NormalizationError(f"{name} must be a valid IPv4 or IPv6 address") from exc


def _port(value: Any, name: str) -> int | None:
    if value is None or value == "":
        return None
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise NormalizationError(f"{name} must be an integer from 1 to 65535") from exc
    if not 1 <= port <= 65535:
        raise NormalizationError(f"{name} must be an integer from 1 to 65535")
    return port


def normalize_event(payload: dict[str, Any], default_source: str = "api") -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise NormalizationError("Each event must be a JSON object")
    raw = dict(payload)
    for alias, canonical in _ALIASES.items():
        if canonical not in raw and alias in raw:
            raw[canonical] = raw[alias]
        if alias != canonical:
            raw.pop(alias, None)

    if "metadata_json" in raw and "metadata" not in raw:
        raw["metadata"] = raw.pop("metadata_json")
    else:
        raw.pop("metadata_json", None)
    try:
        raw = validate_event_shape(raw)
    except ValueError as exc:
        raise NormalizationError(str(exc)) from exc
    timestamp_value = raw.get("timestamp")
    if timestamp_value in (None, ""):
        timestamp = datetime.now(timezone.utc)
    elif isinstance(timestamp_value, (int, float)):
        try:
            timestamp = datetime.fromtimestamp(timestamp_value, timezone.utc)
        except (OverflowError, OSError, ValueError) as exc:
            raise NormalizationError("timestamp is outside the supported range") from exc
    elif isinstance(timestamp_value, str):
        try:
            timestamp = datetime.fromisoformat(timestamp_value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise NormalizationError("timestamp must be ISO-8601 or a Unix timestamp") from exc
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        timestamp = timestamp.astimezone(timezone.utc)
    else:
        raise NormalizationError("timestamp must be a string or Unix timestamp")

    metadata = raw.get("metadata", {})
    if not isinstance(metadata, dict):
        raise NormalizationError("metadata must be a JSON object")
    if len(json.dumps(metadata, default=str)) > 16_384:
        raise NormalizationError("metadata exceeds 16384 characters")

    event_type = _clean_text(raw.get("event_type"), "event_type", 80)
    if not event_type:
        raise NormalizationError("event_type is required")
    severity = (_clean_text(raw.get("severity", "informational"), "severity", 20) or "informational").lower()
    severity_aliases = {"info": "informational", "warning": "medium", "warn": "medium", "error": "high"}
    severity = severity_aliases.get(severity, severity)
    if severity not in SEVERITIES:
        raise NormalizationError(f"severity must be one of: {', '.join(sorted(SEVERITIES))}")

    return {
        "timestamp": timestamp,
        "source_ip": _ip(raw.get("source_ip"), "source_ip"),
        "destination_ip": _ip(raw.get("destination_ip"), "destination_ip"),
        "source_port": _port(raw.get("source_port"), "source_port"),
        "destination_port": _port(raw.get("destination_port"), "destination_port"),
        "protocol": (_clean_text(raw.get("protocol"), "protocol", 16) or "").upper() or None,
        "username": _clean_text(raw.get("username"), "username", 128),
        "hostname": _clean_text(raw.get("hostname"), "hostname", 255),
        "event_type": event_type.lower(),
        "action": _clean_text(raw.get("action"), "action", 80),
        "status": _clean_text(raw.get("status"), "status", 40),
        "process": _clean_text(raw.get("process"), "process", 255),
        "message": _clean_text(raw.get("message"), "message", 2000),
        "severity": severity,
        "source": _clean_text(raw.get("source", default_source), "source", 80) or default_source,
        "metadata_json": metadata,
    }


def parse_syslog_line(line: str) -> dict[str, Any]:
    match = _SYSLOG.match(line.strip())
    if not match:
        return {"event_type": "syslog", "message": line.strip()[:2000], "source": "syslog"}
    fields = match.groupdict()
    timestamp = None
    if fields["timestamp"]:
        try:
            timestamp = datetime.strptime(fields["timestamp"], "%b %d %H:%M:%S").replace(year=datetime.now().year, tzinfo=timezone.utc).isoformat()
        except ValueError:
            timestamp = None
    return {
        "timestamp": timestamp,
        "hostname": fields["host"],
        "process": fields["process"].strip(),
        "message": fields["message"],
        "event_type": "syslog",
        "source": "syslog",
    }
