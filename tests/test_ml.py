from app.ml.feature_engineering import FEATURE_NAMES, event_features
from app.services.ml_engine import MLEngine
from app.services.risk_engine import calculate_risk


def test_feature_engineering_is_numeric_and_stable():
    features = event_features({
        "timestamp": "2026-01-01T10:00:00Z",
        "event_type": "authentication", "status": "failed",
        "source_port": 49152, "destination_port": 443,
        "severity": "high", "message": "example",
    })
    assert len(features) == len(FEATURE_NAMES)
    assert all(isinstance(value, float) for value in features)
    assert features[4] == 1.0
    assert features[8] == 1.0


def test_missing_model_is_explicit_and_fails_safe(tmp_path):
    engine = MLEngine(str(tmp_path / "missing.joblib"), str(tmp_path / "missing.json"))
    result = engine.predict({"event_type": "application"})
    assert not engine.available
    assert result["available"] is False
    assert result["reason"]


def test_risk_score_is_bounded_and_explained():
    score, breakdown, severity = calculate_risk("high", anomaly_score=0.9, frequency=5, correlation_count=3)
    assert 0 <= score <= 100
    assert severity in {"informational", "low", "medium", "high", "critical"}
    assert {"rule_severity", "ml_anomaly", "event_frequency", "asset_criticality", "correlation"} <= breakdown.keys()
