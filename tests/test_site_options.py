from app.options import (
    ALERT_STATUS_OPTIONS,
    INCIDENT_STATUS_OPTIONS,
    REPORT_FORMAT_OPTIONS,
    REPORT_TYPE_OPTIONS,
    SEVERITY_OPTIONS,
    USER_ROLE_OPTIONS,
)


def _assert_option_values(html: str, values: tuple[str, ...]) -> None:
    for value in values:
        assert f'value="{value}"' in html


def test_page_select_options_use_shared_values(client):
    alerts = client.get("/alerts").get_data(as_text=True)
    events = client.get("/events").get_data(as_text=True)
    incidents = client.get("/incidents").get_data(as_text=True)
    reports = client.get("/reports").get_data(as_text=True)
    users = client.get("/users").get_data(as_text=True)

    _assert_option_values(alerts, ALERT_STATUS_OPTIONS)
    _assert_option_values(events, SEVERITY_OPTIONS)
    _assert_option_values(incidents, SEVERITY_OPTIONS)
    _assert_option_values(reports, REPORT_FORMAT_OPTIONS)
    _assert_option_values(users, USER_ROLE_OPTIONS)
    for report_type in REPORT_TYPE_OPTIONS:
        assert f'data-kind="{report_type}"' in reports


def test_dynamic_status_options_are_shared_with_browser(client):
    alerts = client.get("/alerts").get_data(as_text=True)
    incidents = client.get("/incidents").get_data(as_text=True)

    for status in ALERT_STATUS_OPTIONS:
        assert status in alerts
    for status in INCIDENT_STATUS_OPTIONS:
        assert status in incidents
