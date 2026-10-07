from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from flask import current_app

from app import db
from app.models.alert import Alert, AlertEvent
from app.models.asset import Asset
from app.models.event import Event
from app.services.risk_engine import calculate_risk
from app.models.threat_intelligence import ThreatIntelligence


def _fingerprint(rule_id: str, event: Event) -> str:
    window_seconds = max(60, current_app.config["ALERT_DEDUP_MINUTES"] * 60)
    bucket = int(event.timestamp.timestamp() // window_seconds)
    content = f"{rule_id}|{event.source_ip or ''}|{event.username or ''}|{bucket}"
    return hashlib.sha256(content.encode()).hexdigest()


def create_alert(detection: dict[str, Any], event: Event, ml_result: dict[str, Any] | None = None) -> Alert | None:
    fingerprint = _fingerprint(detection["rule_id"], event)
    existing = Alert.query.filter_by(fingerprint=fingerprint).first()
    if existing:
        linked = {link.event_id for link in existing.event_links}
        for event_id in detection.get("event_ids", []):
            if event_id not in linked:
                db.session.add(AlertEvent(alert_id=existing.id, event_id=event_id))
        return existing

    ml_score = ml_result.get("anomaly_score") if ml_result and ml_result.get("available") else None
    asset = Asset.query.filter_by(hostname=event.hostname).first() if event.hostname else None
    intel = ThreatIntelligence.query.filter_by(indicator_type="ip", indicator=event.source_ip).first() if event.source_ip else None
    risk, breakdown, risk_severity = calculate_risk(
        detection["severity"],
        anomaly_score=ml_score,
        frequency=detection.get("frequency", 1),
        correlation_count=max(0, len(detection.get("event_ids", [])) - 1),
        threat_confidence=intel.confidence if intel else 0.0,
        asset_criticality=asset.criticality if asset else 50,
        thresholds=current_app.config["RISK_THRESHOLDS"],
    )
    severity_order = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    severity = max((detection["severity"], risk_severity), key=lambda value: severity_order[value])
    rule_mitre = detection.get("mitre", [])
    alert = Alert(
        fingerprint=fingerprint,
        title=detection["title"],
        description=detection["description"],
        rule_id=detection["rule_id"],
        rule_name=detection["rule_name"],
        severity=severity,
        risk_score=risk,
        confidence=detection["confidence"],
        source_ip=event.source_ip,
        destination_ip=event.destination_ip,
        username=event.username,
        detection_source="rule+ml" if ml_score is not None else "rule",
        anomaly_score=ml_score,
        model_version=ml_result.get("model_version") if ml_score is not None else None,
        evidence=[{"event_id": event_id, "reason": detection["description"]} for event_id in detection.get("event_ids", [])],
        ml_feature_summary=ml_result.get("feature_summary", {}) if ml_result and ml_result.get("available") else {},
        score_breakdown=breakdown,
        mitre=rule_mitre,
        recommended_action=detection["recommended_action"],
        created_at=datetime.now(timezone.utc),
    )
    db.session.add(alert)
    db.session.flush()
    for event_id in detection.get("event_ids", []):
        db.session.add(AlertEvent(alert_id=alert.id, event_id=event_id))
    db.session.flush()
    current_app.logger.info("Alert generated rule_id=%s severity=%s risk=%s", alert.rule_id, alert.severity, alert.risk_score)
    return alert
