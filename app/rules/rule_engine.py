from app.models.event import Event
from app.rules.authentication_rules import failed_authentication_rule
from app.rules.endpoint_rules import suspicious_process_rule
from app.rules.malware_rules import known_malware_indicator_rule
from app.rules.network_rules import destination_port_fanout_rule
from app.rules.phishing_rules import phishing_indicator_rule
from app.services.correlation_engine import correlate_event


def evaluate_event(event: Event) -> list[dict]:
    detections = []
    for rule in (
        failed_authentication_rule,
        destination_port_fanout_rule,
        suspicious_process_rule,
        known_malware_indicator_rule,
        phishing_indicator_rule,
        correlate_event,
    ):
        result = rule(event)
        if result:
            detections.append(result)
    return detections
