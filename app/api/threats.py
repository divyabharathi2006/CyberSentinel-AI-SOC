from flask import current_app, jsonify
from flask_jwt_extended import jwt_required

from app.api import api_bp
from app.services.threat_intel import lookup_indicator, validate_indicator


@api_bp.get("/threat-intel/<path:indicator>")
@jwt_required()
def get_threat_intelligence(indicator: str):
    try:
        normalized = validate_indicator(indicator)
    except ValueError as exc:
        return jsonify(success=False, error={"code": "INVALID_INDICATOR", "message": str(exc)}), 400
    try:
        result = lookup_indicator(indicator, current_app.config["THREAT_INTEL_API_KEY"])
    except ValueError as exc:
        return jsonify(success=False, error={"code": "INVALID_INDICATOR", "message": str(exc)}), 400
    return jsonify(success=True, indicator={"type": normalized[0], "value": normalized[1]}, result=result, enriched=result is not None)
