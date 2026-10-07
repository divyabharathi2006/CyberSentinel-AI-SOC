from __future__ import annotations

from datetime import datetime, timezone

from flask import current_app, jsonify, request
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required

from app import db, limiter
from app.api import api_bp
from app.models.user import User
from app.services.audit_service import record_audit
from app.utils.security import request_ip


@api_bp.post("/auth/login")
@limiter.limit("5 per minute")
def login():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(success=False, error={"code": "INVALID_REQUEST", "message": "A JSON object is required"}), 400
    username = payload.get("username")
    password = payload.get("password")
    if not isinstance(username, str) or not isinstance(password, str) or len(username) > 80 or len(password) > 256:
        return jsonify(success=False, error={"code": "INVALID_CREDENTIALS", "message": "Invalid username or password"}), 401
    user = User.query.filter_by(username=username.strip()).first()
    if not user or not user.is_active or not user.verify_password(password):
        record_audit("login_failed", "authentication", None, user.id if user else None, request_ip())
        db.session.commit()
        return jsonify(success=False, error={"code": "INVALID_CREDENTIALS", "message": "Invalid username or password"}), 401
    user.last_login_at = datetime.now(timezone.utc)
    token = create_access_token(identity=str(user.id))
    record_audit("login", "user", user.id, user.id, request_ip())
    db.session.commit()
    return jsonify(success=True, access_token=token, token_type="Bearer", expires_in=current_app.config["JWT_ACCESS_TOKEN_EXPIRES"], user=user.to_dict())


@api_bp.post("/auth/logout")
@jwt_required()
def logout():
    try:
        user_id = int(get_jwt_identity())
    except (TypeError, ValueError):
        user_id = None
    record_audit("logout", "authentication", user_id, user_id, request_ip())
    db.session.commit()
    return jsonify(success=True, message="Signed out. Remove the bearer token from the client.")


@api_bp.get("/auth/me")
@jwt_required()
def me():
    user = User.query.filter_by(id=int(get_jwt_identity()), is_active=True).first()
    if not user:
        return jsonify(success=False, error={"code": "UNAUTHENTICATED", "message": "Account is unavailable"}), 401
    return jsonify(success=True, user=user.to_dict())
