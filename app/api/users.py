from flask import jsonify, request
from flask_jwt_extended import jwt_required

from app import db
from app.api import api_bp
from app.models.user import ROLES, User
from app.models.audit_log import AuditLog
from app.services.audit_service import record_audit
from app.utils.security import actor_id, request_ip, roles_required


@api_bp.get("/users")
@roles_required("Admin", "Security Manager")
def list_users():
    users = User.query.order_by(User.username.asc()).limit(500).all()
    return jsonify(success=True, items=[user.to_dict() for user in users])


@api_bp.post("/users")
@roles_required("Admin")
def create_user():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(success=False, error={"code": "INVALID_REQUEST", "message": "A JSON object is required"}), 400
    username, email, password, role = (payload.get(name) for name in ("username", "email", "password", "role"))
    if not isinstance(username, str) or not username.strip() or len(username) > 80:
        return jsonify(success=False, error={"code": "INVALID_REQUEST", "message": "username must contain 1 to 80 characters"}), 400
    if not isinstance(email, str) or len(email) > 254 or "@" not in email:
        return jsonify(success=False, error={"code": "INVALID_REQUEST", "message": "A valid email address is required"}), 400
    if not isinstance(role, str) or role not in ROLES:
        return jsonify(success=False, error={"code": "INVALID_REQUEST", "message": f"role must be one of {sorted(ROLES)}"}), 400
    if not isinstance(password, str):
        return jsonify(success=False, error={"code": "INVALID_REQUEST", "message": "A password is required"}), 400
    if User.query.filter((User.username == username.strip()) | (User.email == email.strip().lower())).first():
        return jsonify(success=False, error={"code": "CONFLICT", "message": "Username or email is already registered"}), 409
    user = User(username=username.strip(), email=email.strip().lower(), role=role)
    try:
        user.set_password(password)
    except ValueError as exc:
        return jsonify(success=False, error={"code": "INVALID_REQUEST", "message": str(exc)}), 400
    db.session.add(user)
    db.session.flush()
    record_audit("user_created", "user", user.id, actor_id(), request_ip(), {"role": role})
    db.session.commit()
    return jsonify(success=True, user=user.to_dict()), 201


@api_bp.get("/audit-logs")
@roles_required("Admin", "Security Manager")
def get_audit_logs():
    page = max(1, request.args.get("page", 1, type=int))
    per_page = min(100, max(1, request.args.get("per_page", 50, type=int)))
    pagination = AuditLog.query.order_by(AuditLog.id.desc()).paginate(page=page, per_page=per_page, error_out=False)
    return jsonify(success=True, items=[{
        "id": item.id, "actor_id": item.actor_id, "action": item.action,
        "resource_type": item.resource_type, "resource_id": item.resource_id,
        "ip_address": item.ip_address, "details": item.details,
        "previous_hash": item.previous_hash, "entry_hash": item.entry_hash,
        "created_at": item.created_at.isoformat(),
    } for item in pagination.items])


@api_bp.get("/audit-logs/verify")
@roles_required("Admin", "Security Manager")
def verify_audit_logs():
    from app.services.audit_service import verify_audit_chain

    valid = verify_audit_chain()
    return jsonify(success=valid, audit_chain="valid" if valid else "integrity_check_failed"), 200 if valid else 409
