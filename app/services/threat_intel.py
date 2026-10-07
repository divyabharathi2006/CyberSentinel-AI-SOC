from __future__ import annotations

import ipaddress
import logging
import re
from urllib.parse import quote, urlsplit

import requests

from app import db
from app.models.threat_intelligence import ThreatIntelligence

logger = logging.getLogger(__name__)
_HASH = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))+$")


def validate_indicator(indicator: str) -> tuple[str, str]:
    value = indicator.strip()
    if len(value) > 512 or not value:
        raise ValueError("indicator must contain 1 to 512 characters")
    try:
        return "ip", str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if _HASH.fullmatch(value):
        return "hash", value.lower()
    if len(value) <= 512 and value.startswith(("http://", "https://")):
        parsed = urlsplit(value)
        hostname = parsed.hostname
        if parsed.scheme in {"http", "https"} and hostname and not parsed.username and not parsed.password:
            try:
                address = ipaddress.ip_address(hostname)
            except ValueError:
                address = None
            if address and not address.is_global:
                raise ValueError("URL indicators with non-public IP addresses cannot be sent to an external provider")
            if hostname.lower() in {"localhost", "localhost.localdomain"} or "." not in hostname:
                raise ValueError("URL host must be a public IP address or fully-qualified domain")
            return "url", value
    if _DOMAIN.fullmatch(value):
        return "domain", value.lower()
    raise ValueError("indicator must be an IP address, domain, http(s) URL, or MD5/SHA hash")


def lookup_indicator(indicator: str, api_key: str) -> dict | None:
    indicator_type, normalized = validate_indicator(indicator)
    cached = ThreatIntelligence.query.filter_by(indicator_type=indicator_type, indicator=normalized).first()
    if cached:
        return {
            "indicator_type": cached.indicator_type, "indicator": cached.indicator,
            "reputation": cached.reputation, "confidence": cached.confidence,
            "source": cached.source, "first_seen": cached.first_seen.isoformat() if cached.first_seen else None,
            "last_seen": cached.last_seen.isoformat() if cached.last_seen else None, "tags": cached.tags or [],
        }
    if not api_key:
        return None
    endpoint_type = {"ip": "ip_addresses", "hash": "files", "domain": "domains", "url": "urls"}[indicator_type]
    api_indicator = normalized
    if indicator_type == "url":
        import base64

        api_indicator = base64.urlsafe_b64encode(normalized.encode()).decode().rstrip("=")
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/{endpoint_type}/{quote(api_indicator, safe='')}",
            headers={"x-apikey": api_key},
            timeout=(2, 5),
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        attributes = response.json().get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        total = sum(stats.get(key, 0) for key in ("harmless", "malicious", "suspicious", "undetected", "timeout"))
        detections = stats.get("malicious", 0) + stats.get("suspicious", 0)
        confidence = min(1.0, detections / total) if total else 0.0
        item = ThreatIntelligence(
            indicator_type=indicator_type, indicator=normalized,
            reputation="malicious" if stats.get("malicious", 0) else "suspicious" if stats.get("suspicious", 0) else "no_detections",
            confidence=confidence, source="VirusTotal",
            tags=attributes.get("tags", [])[:50],
            raw_summary={"analysis_stats": stats},
        )
        db.session.add(item)
        db.session.commit()
        return {
            "indicator_type": item.indicator_type, "indicator": item.indicator, "reputation": item.reputation,
            "confidence": item.confidence, "source": item.source, "tags": item.tags,
        }
    except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
        db.session.rollback()
        logger.warning("Threat intelligence lookup failed: %s", exc)
        return None
