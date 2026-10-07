def test_viewer_cannot_ingest_or_update_alert(client, viewer_headers):
    response = client.post("/api/events", headers=viewer_headers, json={"event_type": "application"})
    assert response.status_code == 403


def test_alert_lifecycle_note_and_incident(client, analyst_headers):
    now = "2026-10-01T00:00:00+00:00"
    failures = [{
        "timestamp": now, "event_type": "authentication", "source_ip": "198.51.100.100",
        "username": "synthetic", "status": "failed",
    } for _ in range(5)]
    ingested = client.post("/api/events", headers=analyst_headers, json=failures)
    assert ingested.status_code == 201
    alert_id = ingested.json["alerts"][0]["id"]
    updated = client.patch(f"/api/alerts/{alert_id}", headers=analyst_headers, json={"status": "ACKNOWLEDGED", "note": "Reviewed synthetic lab evidence"})
    assert updated.status_code == 200
    assert updated.json["alert"]["status"] == "ACKNOWLEDGED"
    assert updated.json["alert"]["analyst_notes"][0]["note"] == "Reviewed synthetic lab evidence"
    created = client.post(f"/api/alerts/{alert_id}/incidents", headers=analyst_headers)
    assert created.status_code == 201
    assert alert_id in created.json["incident"]["alert_ids"]


def test_invalid_alert_status_rejected(client, analyst_headers):
    response = client.patch("/api/alerts/1", headers=analyst_headers, json={"status": "INVALID"})
    assert response.status_code == 404
