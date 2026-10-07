_SUSPICIOUS_PROCESS_TERMS = ("mimikatz", "credential dump", "encodedcommand")


def suspicious_process_rule(event):
    process_data = f"{event.process or ''} {event.message or ''}".lower()
    match = next((term for term in _SUSPICIOUS_PROCESS_TERMS if term in process_data), None)
    if not match:
        return None
    return {
        "rule_id": "ENDPOINT-001",
        "rule_name": "Configured suspicious process indicator",
        "title": "Configured suspicious process indicator observed",
        "description": f"Endpoint telemetry contains the configured indicator {match!r}. Validate the process, parent process, and host context.",
        "severity": "high",
        "confidence": 0.72,
        "event_ids": [event.id],
        "frequency": 1,
        "mitre": [],
        "recommended_action": "Preserve endpoint telemetry and investigate process lineage using authorized EDR tools.",
    }
