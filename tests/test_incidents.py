from datetime import datetime, timezone


def test_create_update_and_list_incident(client, analyst_headers):
    created = client.post("/api/incidents", headers=analyst_headers, json={
        "title": "Synthetic investigation",
        "description": "Investigation for a synthetic lab event.",
        "severity": "medium",
        "alert_ids": [],
    })
    assert created.status_code == 201
    incident_id = created.json["incident"]["id"]
    updated = client.patch(f"/api/incidents/{incident_id}", headers=analyst_headers, json={
        "status": "Investigating", "note": "Validated synthetic evidence",
    })
    assert updated.status_code == 200
    assert updated.json["incident"]["status"] == "Investigating"
    assert len(updated.json["incident"]["timeline"]) == 2
    listed = client.get("/api/incidents", headers=analyst_headers)
    assert listed.json["pagination"]["total"] == 1


def test_invalid_incident_input_rejected(client, analyst_headers):
    response = client.post("/api/incidents", headers=analyst_headers, json={"title": 42, "description": []})
    assert response.status_code == 400
    unknown_alert = client.post("/api/incidents", headers=analyst_headers, json={
        "title": "Bad reference", "description": "Test", "alert_ids": [9000],
    })
    assert unknown_alert.status_code == 400


def test_incident_attack_timeline_includes_linked_events_and_alert(client, analyst_headers):
    alerts = []
    for _ in range(5):
        response = client.post("/api/events", headers=analyst_headers, json={
            "event_type": "authentication",
            "source_ip": "198.51.100.25",
            "username": "synthetic-user",
            "status": "failed",
            "severity": "medium",
            "message": "Synthetic failed login for timeline test",
        })
        assert response.status_code == 201
        alerts.extend(response.json["alerts"])
    assert alerts
    incident = client.post("/api/incidents", headers=analyst_headers, json={
        "title": "Synthetic timeline",
        "description": "Timeline integration test",
        "alert_ids": [alerts[0]["id"]],
    })
    assert incident.status_code == 201
    incident_id = incident.json["incident"]["id"]

    timeline = client.get(f"/api/timeline/{incident_id}", headers=analyst_headers)
    assert timeline.status_code == 200
    assert timeline.json["event_count"] >= 1
    assert timeline.json["alert_count"] == 1
    kinds = [item["kind"] for item in timeline.json["timeline"]]
    assert "event" in kinds
    assert "alert" in kinds
    normalized_times = []
    for item in timeline.json["timeline"]:
        value = datetime.fromisoformat(item["at"].replace("Z", "+00:00"))
        normalized_times.append(value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value)
    assert normalized_times == sorted(normalized_times)


def test_timeline_missing_incident_is_not_found(client, analyst_headers):
    assert client.get("/api/timeline/9000", headers=analyst_headers).status_code == 404
