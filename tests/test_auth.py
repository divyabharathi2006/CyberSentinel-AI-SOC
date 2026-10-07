from app.models.user import User


def test_password_is_hashed_and_policy_enforced(app):
    with app.app_context():
        user = User.query.filter_by(username="analyst").first()
        assert user.password_hash != "Safe-Test-Password-123"
        assert user.verify_password("Safe-Test-Password-123")
        assert not user.verify_password("incorrect")
        try:
            user.set_password("weak")
        except ValueError as error:
            assert "12 characters" in str(error)
        else:
            raise AssertionError("weak password was accepted")


def test_login_and_me(client):
    login = client.post("/api/auth/login", json={"username": "analyst", "password": "Safe-Test-Password-123"})
    headers = {"Authorization": f"Bearer {login.json['access_token']}"}
    response = client.get("/api/auth/me", headers=headers)
    assert response.status_code == 200
    assert response.json["user"]["role"] == "SOC Analyst"


def test_invalid_login_does_not_reveal_account(client):
    response = client.post("/api/auth/login", json={"username": "missing", "password": "not-a-password"})
    assert response.status_code == 401
    assert response.json["error"]["message"] == "Invalid username or password"
