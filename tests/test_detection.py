from datetime import datetime, timedelta, timezone

from app import db
from app.models.alert import Alert
from app.models.threat_intelligence import ThreatIntelligence


def test_failed_logins_generate_explained_alert(client, analyst_headers):
    start = datetime.now(timezone.utc)
    payload = [{
        "timestamp": (start + timedelta(seconds=index * 10)).isoformat(),
        "event_type": "authentication", "source_ip": "198.51.100.30",
        "username": "synthetic-user", "status": "failed",
        "severity": "medium", "message": "Synthetic failed login",
    } for index in range(5)]
    response = client.post("/api/events", headers=analyst_headers, json=payload)
    assert response.status_code == 201
    assert response.json["accepted"] == 5
    generated = [item for item in response.json["alerts"] if item["rule_id"] == "AUTH-001"]
    assert generated
    alert = generated[0]
    assert "Potential brute-force" in alert["title"]
    assert alert["risk_score"] > 0
    assert alert["score_breakdown"]["rule_severity"] > 0
    assert len(alert["event_ids"]) == 5


def test_success_after_failures_creates_correlated_signal(client, analyst_headers):
    start = datetime.now(timezone.utc)
    payload = [{
        "timestamp": (start + timedelta(seconds=index * 8)).isoformat(),
        "event_type": "authentication", "source_ip": "198.51.100.44",
        "username": "synthetic-user", "status": "failed" if index < 4 else "success",
        "message": "Synthetic correlation test",
    } for index in range(5)]
    client.post("/api/events", headers=analyst_headers, json=payload)
    with client.application.app_context():
        correlated = Alert.query.filter_by(rule_id="AUTH-001-CORRELATED").first()
        assert correlated is not None
        assert len(correlated.event_links) == 5


def test_network_port_fanout_rule(client, analyst_headers):
    now = datetime.now(timezone.utc)
    payload = [{
        "timestamp": (now + timedelta(seconds=idx)).isoformat(),
        "event_type": "network_connection", "source_ip": "203.0.113.9",
        "destination_ip": "192.0.2.4", "destination_port": 1000 + idx,
        "status": "observed",
    } for idx in range(8)]
    response = client.post("/api/events", headers=analyst_headers, json=payload)
    assert response.status_code == 201
    assert any(alert["rule_id"] == "NET-001" for alert in response.json["alerts"])


def test_ml_unavailable_keeps_rule_detections_active(client, analyst_headers):
    response = client.post("/api/health")
    assert response.status_code == 405
    health = client.get("/api/health")
    assert health.json["components"]["ml_engine"] == "unavailable"
    assert health.json["components"]["log_ingestion"] == "healthy"


def test_cached_malicious_file_hash_generates_indicator_alert(client, analyst_headers, app):
    file_hash = "a" * 64
    with app.app_context():
        db.session.add(ThreatIntelligence(
            indicator_type="hash", indicator=file_hash, reputation="malicious",
            confidence=0.9, source="test-feed", tags=["test"],
        ))
        db.session.commit()

    response = client.post("/api/events", headers=analyst_headers, json={
        "event_type": "endpoint_security",
        "source_ip": "192.0.2.44",
        "metadata": {"sha256": file_hash},
        "message": "Synthetic endpoint file indicator.",
    })
    assert response.status_code == 201
    alert = next(item for item in response.json["alerts"] if item["rule_id"] == "MALWARE-001")
    assert alert["severity"] == "critical"
    assert "cached malicious" in alert["description"]


def test_phishing_indicators_are_static_and_explained(client, analyst_headers):
    response = client.post("/api/events", headers=analyst_headers, json={
        "event_type": "email_security",
        "metadata": {
            "url": "https://192.0.2.80/account",
            "sender_domain": "trusted.example",
        },
        "message": "Synthetic email link metadata; do not open.",
    })
    assert response.status_code == 201
    alert = next(item for item in response.json["alerts"] if item["rule_id"] == "PHISHING-001")
    assert alert["severity"] == "medium"
    assert "No URL was visited" in alert["description"]
