from __future__ import annotations

import pytest

from app import create_app, db
from app.models.user import User


@pytest.fixture()
def app(tmp_path):
    database = tmp_path / "test.sqlite"
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret-key-that-is-never-used-outside-tests",
        "JWT_SECRET_KEY": "test-jwt-key-that-is-never-used-outside-tests",
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database.as_posix()}",
        "RATELIMIT_ENABLED": False,
        "ELASTICSEARCH_URL": "",
        "ML_MODEL_PATH": str(tmp_path / "missing.joblib"),
        "ML_METADATA_PATH": str(tmp_path / "missing.json"),
        "ENABLE_SYSLOG": False,
    })
    with app.app_context():
        db.create_all()
        for role, username in (("Admin", "admin"), ("SOC Analyst", "analyst"), ("Viewer", "viewer"), ("Security Manager", "manager")):
            user = User(username=username, email=f"{username}@example.invalid", role=role)
            user.set_password("Safe-Test-Password-123")
            db.session.add(user)
        db.session.commit()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def auth_header(client, username="analyst"):
    response = client.post("/api/auth/login", json={"username": username, "password": "Safe-Test-Password-123"})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json['access_token']}"}


@pytest.fixture()
def analyst_headers(client):
    return auth_header(client, "analyst")


@pytest.fixture()
def viewer_headers(client):
    return auth_header(client, "viewer")


@pytest.fixture()
def admin_headers(client):
    return auth_header(client, "admin")
