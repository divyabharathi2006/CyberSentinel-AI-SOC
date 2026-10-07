from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from app.models.event import Event
from app.models.threat_intelligence import ThreatIntelligence

_URL_FIELDS = ("url", "uri", "link")
_DOMAIN_FIELDS = ("domain", "sender_domain", "from_domain", "link_domain")


def phishing_indicator_rule(event: Event) -> dict | None:
    metadata = event.metadata_json or {}
    candidate = next(
        (metadata[key].strip() for key in _URL_FIELDS if isinstance(metadata.get(key), str) and metadata[key].strip()),
        None,
    )
    domain = next(
        (metadata[key].strip().lower().rstrip(".") for key in _DOMAIN_FIELDS if isinstance(metadata.get(key), str) and metadata[key].strip()),
        None,
    )
    if not candidate and not domain:
        return None

    url = candidate if candidate and candidate.startswith(("http://", "https://")) else None
    hostname = urlsplit(url).hostname.lower().rstrip(".") if url else domain
    if not hostname:
        return None

    reasons = []
    reputation = None
    indicators = [("url", url)] if url else []
    indicators.append(("domain", hostname))
    for indicator_type, indicator in indicators:
        intel = ThreatIntelligence.query.filter_by(
            indicator_type=indicator_type, indicator=indicator
        ).first()
        if intel and intel.reputation in {"malicious", "suspicious"}:
            reputation = intel
            reasons.append(f"cached {intel.reputation} threat-intelligence match")
            break

    try:
        ipaddress.ip_address(hostname)
        reasons.append("URL or link uses an IP-literal host")
    except ValueError:
        if hostname.startswith("xn--") or ".xn--" in hostname:
            reasons.append("domain contains an IDN/Punycode label")

    sender_domain = next(
        (metadata[key].strip().lower().rstrip(".") for key in ("sender_domain", "from_domain") if isinstance(metadata.get(key), str) and metadata[key].strip()),
        None,
    )
    if sender_domain and hostname != sender_domain and not hostname.endswith(f".{sender_domain}"):
        reasons.append("link host differs from the supplied sender domain")
    if not reasons:
        return None

    confidence = max(0.55, min(1.0, reputation.confidence if reputation else 0.62))
    severity = "high" if reputation and reputation.reputation == "malicious" else "medium"
    return {
        "rule_id": "PHISHING-001",
        "rule_name": "Static phishing indicator analysis",
        "title": "Potential phishing indicator requires review",
        "description": f"String-only analysis found: {'; '.join(reasons)}. No URL was visited and the signal does not confirm phishing.",
        "severity": severity,
        "confidence": confidence,
        "event_ids": [event.id],
        "frequency": 1,
        "mitre": [{"id": "T1566", "name": "Phishing", "tactic": "Initial Access", "reason": "Telemetry contains a static link/domain indicator requiring analyst validation."}],
        "recommended_action": "Do not open the link. Validate message headers and domain context using approved, isolated security tooling.",
    }
