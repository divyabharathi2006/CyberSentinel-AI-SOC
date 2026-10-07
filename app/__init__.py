from __future__ import annotations

import logging
import os
import secrets
import warnings
from pathlib import Path

from flask import Flask, jsonify, render_template, request
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_migrate import Migrate
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.exceptions import HTTPException

from app.config import Config

db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()
limiter = Limiter(key_func=get_remote_address, default_limits=[])
socketio = SocketIO(cors_allowed_origins=[], async_mode="threading")


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(
        __name__,
        instance_relative_config=True,
        template_folder="../frontend/templates",
        static_folder="../frontend/static",
    )
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    if not app.config["SECRET_KEY"] or not app.config["JWT_SECRET_KEY"]:
        if os.getenv("FLASK_ENV", "").lower() == "production":
            raise RuntimeError("SECRET_KEY and JWT_SECRET_KEY must be configured in production")
        if not app.config["SECRET_KEY"]:
            app.config["SECRET_KEY"] = secrets.token_urlsafe(48)
        if not app.config["JWT_SECRET_KEY"]:
            app.config["JWT_SECRET_KEY"] = secrets.token_urlsafe(48)
        warnings.warn("Ephemeral development secrets are active; configure persistent secrets before deployment", RuntimeWarning)
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    limiter.init_app(app)
    CORS(app, resources={r"/api/*": {"origins": app.config["CORS_ORIGINS"]}})
    socketio.init_app(app, cors_allowed_origins=app.config["CORS_ORIGINS"])

    from app.api import api_bp
    from app.models import (  # noqa: F401
        Alert,
        Asset,
        AuditLog,
        Event,
        Incident,
        IncidentAlert,
        ModelVersion,
        ThreatIntelligence,
        User,
    )
    from app.services.syslog_listener import start_syslog_listener
    from app.web import web_bp

    app.register_blueprint(api_bp, url_prefix="/api")
    app.register_blueprint(web_bp)

    @app.context_processor
    def inject_site_options():
        from app.options import (
            ALERT_STATUS_OPTIONS,
            INCIDENT_STATUS_OPTIONS,
            REPORT_FORMAT_OPTIONS,
            REPORT_TYPE_OPTIONS,
            SEVERITY_OPTIONS,
            USER_ROLE_OPTIONS,
        )

        return {
            "site_options": {
                "alert_statuses": ALERT_STATUS_OPTIONS,
                "incident_statuses": INCIDENT_STATUS_OPTIONS,
                "report_formats": REPORT_FORMAT_OPTIONS,
                "report_types": REPORT_TYPE_OPTIONS,
                "severities": SEVERITY_OPTIONS,
                "user_roles": USER_ROLE_OPTIONS,
            }
        }

    logging.basicConfig(
        level=getattr(logging, app.config["LOG_LEVEL"].upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    app.logger.info("CyberSentinel AI SOC initialized")

    @app.errorhandler(404)
    def not_found(error: Exception):
        if request.path.startswith("/api/"):
            return jsonify(success=False, error={"code": "NOT_FOUND", "message": "Resource not found"}), 404
        return render_template("login.html"), 404

    @app.errorhandler(413)
    def too_large(error: Exception):
        return jsonify(success=False, error={"code": "PAYLOAD_TOO_LARGE", "message": "Request exceeds the configured size limit"}), 413

    @app.errorhandler(SQLAlchemyError)
    def database_error(error: SQLAlchemyError):
        db.session.rollback()
        app.logger.exception("Database operation failed")
        return jsonify(success=False, error={"code": "DATABASE_ERROR", "message": "The database operation could not be completed"}), 503

    @app.errorhandler(HTTPException)
    def http_error(error: HTTPException):
        if request.path.startswith("/api/"):
            code = error.name.upper().replace(" ", "_")
            return jsonify(success=False, error={"code": code, "message": error.description}), error.code
        return error

    @app.errorhandler(Exception)
    def unexpected_error(error: Exception):
        app.logger.exception("Unhandled application error")
        if request.path.startswith("/api/"):
            return jsonify(success=False, error={"code": "INTERNAL_ERROR", "message": "An unexpected server error occurred"}), 500
        return "An unexpected server error occurred.", 500

    if app.config["ENABLE_SYSLOG"] and (not app.debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true"):
        start_syslog_listener(app)

    return app
