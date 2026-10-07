from flask import g


def test_health_and_dashboard_summary(client, analyst_headers):
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json["components"]["application"] == "healthy"
    summary = client.get("/api/dashboard/summary", headers=analyst_headers)
    assert summary.status_code == 200
    assert summary.json["summary"]["total_events"] == 0
    assert summary.json["summary"]["active_suspicious_ips"] == 0
    assert summary.json["summary"]["top_destination_ports"] == []


def test_network_and_ml_analytics_endpoints(client, analyst_headers):
    assert client.get("/api/network/summary").status_code == 401
    assert client.get("/api/ml/analytics").status_code == 401
    network = client.get("/api/network/summary", headers=analyst_headers)
    ml = client.get("/api/ml/analytics", headers=analyst_headers)
    assert network.status_code == 200
    assert network.json["summary"]["network_events"] == 0
    assert ml.status_code == 200
    assert ml.json["analytics"]["sample_count"] == 0
    assert "not proof of malicious activity" in ml.json["analytics"]["interpretation"]


def test_unauthorized_and_role_protected_endpoints(client, viewer_headers):
    assert client.get("/api/events").status_code == 401
    assert client.get("/api/users", headers=viewer_headers).status_code == 403


def test_unknown_api_path_has_consistent_error(client):
    response = client.get("/api/nonexistent")
    assert response.status_code == 404
    assert response.json["error"]["code"] == "NOT_FOUND"


def test_runtime_settings_are_authenticated_and_secret_redacted(client, analyst_headers):
    assert client.get("/api/settings").status_code == 401
    response = client.get("/api/settings", headers=analyst_headers)
    assert response.status_code == 200
    settings = response.json["settings"]
    assert settings["application"]["database"] == "sqlite"
    assert settings["integrations"]["threat_intelligence_configured"] is False
    assert "THREAT_INTEL_API_KEY" not in str(settings)
    assert "JWT_SECRET_KEY" not in str(settings)


def test_demo_generation_ingests_synthetic_events_with_role_check(client, analyst_headers, viewer_headers):
    denied = client.post("/api/demo/generate", headers=viewer_headers, json={"count": 1})
    assert denied.status_code == 403
    g.pop("current_user", None)

    invalid = client.post("/api/demo/generate", headers=analyst_headers, json={"count": 0})
    assert invalid.status_code == 400

    g.pop("current_user", None)
    response = client.post("/api/demo/generate", headers=analyst_headers, json={"count": 1})
    assert response.status_code == 201
    assert response.json["accepted"] == 18
    assert client.get("/api/events?source_ip=198.51.100.25", headers=analyst_headers).json["pagination"]["total"] == 6
