from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from app import db
from app.models.audit_log import AuditLog


def record_audit(action: str, resource_type: str, resource_id: str | int | None, actor_id: int | None, ip_address: str | None, details: dict | None = None) -> AuditLog:
    previous = AuditLog.query.order_by(AuditLog.id.desc()).first()
    previous_hash = previous.entry_hash if previous else "GENESIS"
    created = datetime.now(timezone.utc)
    safe_details = details or {}
    payload = {
        "actor_id": actor_id, "action": action, "resource_type": resource_type,
        "resource_id": str(resource_id) if resource_id is not None else None,
        "ip_address": ip_address, "details": safe_details, "previous_hash": previous_hash,
        "created_at": created.isoformat(),
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
    entry = AuditLog(
        actor_id=actor_id, action=action, resource_type=resource_type,
        resource_id=payload["resource_id"], ip_address=ip_address, details=safe_details,
        previous_hash=previous_hash, entry_hash=digest, created_at=created,
    )
    db.session.add(entry)
    return entry


def verify_audit_chain() -> bool:
    previous_hash = "GENESIS"
    for entry in AuditLog.query.order_by(AuditLog.id.asc()).yield_per(250):
        created = entry.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        payload = {
            "actor_id": entry.actor_id, "action": entry.action, "resource_type": entry.resource_type,
            "resource_id": entry.resource_id, "ip_address": entry.ip_address,
            "details": entry.details or {}, "previous_hash": previous_hash,
            "created_at": created.isoformat(),
        }
        expected = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
        if entry.previous_hash != previous_hash or entry.entry_hash != expected:
            return False
        previous_hash = entry.entry_hash
    return True
