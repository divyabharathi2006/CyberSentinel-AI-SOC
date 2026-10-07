from __future__ import annotations

from functools import wraps
from typing import Callable

from flask import g, jsonify, request
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request

from app.models.user import User


def current_user() -> User | None:
    cached = getattr(g, "current_user", None)
    if cached is not None:
        return cached
    identity = get_jwt_identity()
    if identity is None:
        return None
    try:
        user = db_user_by_id(int(identity))
    except (TypeError, ValueError):
        user = None
    g.current_user = user
    return user


def db_user_by_id(user_id: int) -> User | None:
    return User.query.filter_by(id=user_id, is_active=True).first()


def roles_required(*roles: str) -> Callable:
    def decorator(function: Callable) -> Callable:
        @wraps(function)
        def wrapped(*args, **kwargs):
            verify_jwt_in_request()
            user = current_user()
            if user is None:
                return jsonify(success=False, error={"code": "UNAUTHENTICATED", "message": "Valid authentication is required"}), 401
            if user.role not in roles:
                return jsonify(success=False, error={"code": "FORBIDDEN", "message": "Your role cannot perform this action"}), 403
            return function(*args, **kwargs)
        return wrapped
    return decorator


def actor_id() -> int | None:
    user = current_user()
    return user.id if user else None


def request_ip() -> str | None:
    if request.remote_addr:
        return request.remote_addr[:45]
    return None
