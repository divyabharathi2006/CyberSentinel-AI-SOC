from flask import Blueprint, render_template

web_bp = Blueprint("web", __name__)


@web_bp.get("/")
def home():
    return render_template("dashboard.html")


@web_bp.get("/login")
def login_page():
    return render_template("login.html")


@web_bp.get("/<page>")
def page(page: str):
    templates = {
        "dashboard": "dashboard.html",
        "network": "network.html",
        "events": "events.html",
        "alerts": "alerts.html",
        "incidents": "incidents.html",
        "timeline": "timeline.html",
        "threat-intel": "threat-intel.html",
        "ml-analytics": "ml-analytics.html",
        "reports": "reports.html",
        "settings": "settings.html",
        "health": "health.html",
        "users": "users.html",
    }
    template = templates.get(page)
    if not template:
        return render_template("login.html"), 404
    return render_template(template)
