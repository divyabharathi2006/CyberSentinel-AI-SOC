from app.models.event import Event
from app.services.log_normalizer import NormalizationError, normalize_event


def test_normalization_canonicalizes_aliases_and_timestamp():
    result = normalize_event({
        "src_ip": "198.51.100.10",
        "user": "synthetic-user",
        "type": "Authentication",
        "status": "failed",
        "severity": "warning",
    })
    assert result["source_ip"] == "198.51.100.10"
    assert result["username"] == "synthetic-user"
    assert result["event_type"] == "authentication"
    assert result["severity"] == "medium"
    assert result["timestamp"].tzinfo is not None


def test_unknown_source_fields_are_retained_as_metadata():
    result = normalize_event({"event_type": "network", "vendor_event_id": "evt-3"})
    assert result["metadata_json"] == {"vendor_event_id": "evt-3"}


def test_invalid_ip_and_payload_limits_are_rejected():
    try:
        normalize_event({"event_type": "authentication", "source_ip": "not-an-ip"})
    except NormalizationError as error:
        assert "valid IPv4 or IPv6" in str(error)
    else:
        raise AssertionError("invalid IP accepted")
    try:
        normalize_event({"event_type": "authentication", "message": "x" * 2001})
    except NormalizationError as error:
        assert "maximum length" in str(error)
    else:
        raise AssertionError("oversized message accepted")


def test_event_ingestion_and_filters(client, analyst_headers):
    response = client.post("/api/events", headers=analyst_headers, json={
        "event_type": "application", "source_ip": "192.0.2.9",
        "username": "lab-user", "message": "<script>alert(1)</script>",
    })
    assert response.status_code == 201
    assert response.json["accepted"] == 1
    result = client.get("/api/events?q=lab-user", headers=analyst_headers)
    assert result.status_code == 200
    assert result.json["items"][0]["username"] == "lab-user"
    assert "<script>" in result.json["items"][0]["message"]


def test_malformed_event_and_missing_event(client, analyst_headers):
    invalid = client.post("/api/events", headers=analyst_headers, json={"event_type": "authentication", "source_ip": "bad"})
    assert invalid.status_code == 400
    missing = client.get("/api/events/9000", headers=analyst_headers)
    assert missing.status_code == 404


def test_event_model_persists_metadata(app):
    with app.app_context():
        event = Event(event_type="application", severity="low", metadata_json={"source": "test"})
        from app import db
        db.session.add(event)
        db.session.commit()
        assert db.session.get(Event, event.id).metadata_json == {"source": "test"}
