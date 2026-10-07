from __future__ import annotations

from app.config import Config

SEVERITY_BASE = {"informational": 5, "low": 20, "medium": 45, "high": 68, "critical": 82}


def calculate_risk(
    severity: str,
    anomaly_score: float | None = None,
    frequency: int = 1,
    correlation_count: int = 0,
    threat_confidence: float = 0.0,
    asset_criticality: int = 50,
    thresholds: dict[str, int] | None = None,
) -> tuple[int, dict[str, int], str]:
    base = SEVERITY_BASE.get(severity.lower(), 5)
    factors = {
        "rule_severity": base,
        "ml_anomaly": round(max(0.0, min(1.0, anomaly_score or 0.0)) * 22),
        "event_frequency": min(15, max(0, frequency - 1) * 3),
        "asset_criticality": round(max(0, min(100, asset_criticality)) * 0.10),
        "threat_intelligence": round(max(0.0, min(1.0, threat_confidence)) * 10),
        "correlation": min(15, max(0, correlation_count) * 5),
    }
    score = min(100, sum(factors.values()))
    configured = thresholds or Config.RISK_THRESHOLDS
    level = "informational"
    for candidate in ("low", "medium", "high", "critical"):
        if score >= configured[candidate]:
            level = candidate
    return score, factors, level
