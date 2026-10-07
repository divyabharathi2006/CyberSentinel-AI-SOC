from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone


def generate_events(count: int = 80) -> list[dict]:
    rng = random.Random(731)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    events = []
    usernames = ["lab-analyst", "lab-operator", "service-account"]
    for index in range(count):
        events.append({
            "timestamp": (now - timedelta(minutes=count - index)).isoformat(),
            "source_ip": f"192.0.2.{rng.randint(10, 240)}",
            "destination_ip": "203.0.113.20",
            "destination_port": rng.choice([443, 443, 443, 53]),
            "protocol": rng.choice(["TCP", "UDP"]),
            "username": rng.choice(usernames),
            "hostname": f"lab-host-{rng.randint(1, 6):02d}",
            "event_type": rng.choice(["authentication", "network_connection", "application"]),
            "action": "observe",
            "status": rng.choice(["success", "success", "accepted"]),
            "severity": "informational",
            "source": "synthetic-lab",
            "message": "Synthetic baseline telemetry; not collected from a real person or system.",
        })
    scenario_ip = "198.51.100.25"
    start = now + timedelta(seconds=1)
    for attempt in range(5):
        events.append({
            "timestamp": (start + timedelta(seconds=attempt * 12)).isoformat(),
            "source_ip": scenario_ip, "destination_ip": "203.0.113.20",
            "username": "synthetic-test-user", "hostname": "lab-auth-01",
            "event_type": "authentication", "action": "login", "status": "failed",
            "severity": "medium", "source": "synthetic-lab",
            "message": "Synthetic failed authentication used to demonstrate defensive detection.",
        })
    events.append({
        "timestamp": (start + timedelta(seconds=68)).isoformat(),
        "source_ip": scenario_ip, "destination_ip": "203.0.113.20",
        "username": "synthetic-test-user", "hostname": "lab-auth-01",
        "event_type": "authentication", "action": "login", "status": "success",
        "severity": "medium", "source": "synthetic-lab",
        "message": "Synthetic success after failed attempts to exercise correlation logic.",
    })
    network_start = start + timedelta(minutes=2)
    for port in range(20, 30):
        events.append({
            "timestamp": (network_start + timedelta(seconds=port - 20)).isoformat(),
            "source_ip": "203.0.113.77", "destination_ip": "192.0.2.55",
            "destination_port": port, "protocol": "TCP", "hostname": "lab-network-01",
            "event_type": "network_connection", "action": "connect", "status": "observed",
            "severity": "low", "source": "synthetic-lab",
            "message": "Synthetic network telemetry; confirm approved asset discovery context.",
        })
    events.append({
        "timestamp": (network_start + timedelta(minutes=1)).isoformat(),
        "source_ip": "192.0.2.44", "hostname": "lab-endpoint-02",
        "event_type": "endpoint_process", "process": "encodedcommand",
        "severity": "high", "source": "synthetic-lab",
        "message": "Synthetic configured process indicator for rule validation; not an executable payload.",
    })
    return events
