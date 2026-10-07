from app.services.audit_service import record_audit, verify_audit_chain
from app.services.threat_intel import validate_indicator


def test_audit_chain_detects_tampering(app):
    from app import db
    from app.models.audit_log import AuditLog

    with app.app_context():
        record_audit("test", "resource", "1", None, "127.0.0.1", {"safe": True})
        db.session.commit()
        assert verify_audit_chain()
        row = AuditLog.query.first()
        row.details = {"safe": False}
        db.session.commit()
        assert not verify_audit_chain()


def test_indicator_validation_accepts_safe_types_and_rejects_urls():
    assert validate_indicator("198.51.100.1") == ("ip", "198.51.100.1")
    assert validate_indicator("example.invalid") == ("domain", "example.invalid")
    assert validate_indicator("a" * 64) == ("hash", "a" * 64)
    assert validate_indicator("https://example.invalid/path") == ("url", "https://example.invalid/path")
    try:
        validate_indicator("http://127.0.0.1/private")
    except ValueError:
        pass
    else:
        raise AssertionError("URL indicator should not be accepted by this provider adapter")


def test_user_password_not_returned_and_role_is_enforced(client, admin_headers):
    created = client.post("/api/users", headers=admin_headers, json={
        "username": "new-analyst", "email": "new@example.invalid",
        "password": "Strong-Passphrase-123", "role": "SOC Analyst",
    })
    assert created.status_code == 201
    assert "password" not in created.json["user"]
    assert "password_hash" not in created.json["user"]
    weak = client.post("/api/users", headers=admin_headers, json={
        "username": "bad", "email": "bad@example.invalid", "password": "weak", "role": "Admin",
    })
    assert weak.status_code == 400
