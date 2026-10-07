from flask import jsonify, make_response, request
from flask_jwt_extended import jwt_required

from app import db
from app.api import api_bp
from app.options import REPORT_FORMAT_OPTIONS, REPORT_TYPE_OPTIONS
from app.services.audit_service import record_audit
from app.services.report_service import render_report
from app.utils.security import actor_id, request_ip


@api_bp.get("/reports")
@jwt_required()
def reports():
    report_type = request.args.get("type", "alerts")
    format_name = request.args.get("format", "json").lower()
    if report_type not in REPORT_TYPE_OPTIONS:
        allowed = ", ".join(REPORT_TYPE_OPTIONS)
        return (
            jsonify(success=False, error={"code": "INVALID_REQUEST", "message": f"type must be one of: {allowed}"}),
            400,
        )
    if format_name not in REPORT_FORMAT_OPTIONS:
        allowed = ", ".join(REPORT_FORMAT_OPTIONS)
        return (
            jsonify(success=False, error={"code": "INVALID_REQUEST", "message": f"format must be one of: {allowed}"}),
            400,
        )
    try:
        content, content_type, filename = render_report(report_type, format_name)
    except ValueError as exc:
        return jsonify(success=False, error={"code": "INVALID_REQUEST", "message": str(exc)}), 400
    record_audit("report_generated", "report", report_type, actor_id(), request_ip(), {"format": format_name})
    db.session.commit()
    response = make_response(content)
    response.headers["Content-Type"] = content_type
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response
