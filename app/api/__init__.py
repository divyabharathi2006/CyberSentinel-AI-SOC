from flask import Blueprint

api_bp = Blueprint("api", __name__)

from app.api import (  # noqa: E402,F401
    alerts,
    auth,
    dashboard,
    events,
    health,
    incidents,
    ml_analytics,
    network,
    pipeline,
    realtime,
    reports,
    settings,
    threats,
    users,
)
