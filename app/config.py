from __future__ import annotations

import os
from pathlib import Path

import yaml
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")
CONFIG_PATH = Path(os.getenv("CONFIG_FILE", BASE_DIR / "config.yaml"))
try:
    _CONFIG_DATA = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8")) if CONFIG_PATH.is_file() else {}
except (OSError, yaml.YAMLError) as exc:
    raise RuntimeError(f"Could not read configuration file {CONFIG_PATH}") from exc
_CONFIG_DATA = _CONFIG_DATA if isinstance(_CONFIG_DATA, dict) else {}
_DETECTION = _CONFIG_DATA.get("detection", {})
_AUTH_DETECTION = _DETECTION.get("authentication", {}) if isinstance(_DETECTION, dict) else {}
_NETWORK_DETECTION = _DETECTION.get("network", {}) if isinstance(_DETECTION, dict) else {}
_ANOMALY_DETECTION = _DETECTION.get("anomaly", {}) if isinstance(_DETECTION, dict) else {}
_RISK = _CONFIG_DATA.get("risk", {})


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "")
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL", f"sqlite:///{(BASE_DIR / 'instance' / 'cybersentinel.db').as_posix()}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}
    JWT_ACCESS_TOKEN_EXPIRES = int(os.getenv("JWT_ACCESS_TOKEN_MINUTES", "30")) * 60
    JWT_TOKEN_LOCATION = ["headers"]
    JWT_HEADER_NAME = "Authorization"
    JWT_HEADER_TYPE = "Bearer"
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", "1048576"))
    CORS_ORIGINS = [origin.strip() for origin in os.getenv("CORS_ORIGINS", "").split(",") if origin.strip()]
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "")
    ELASTICSEARCH_USERNAME = os.getenv("ELASTICSEARCH_USERNAME", "")
    ELASTICSEARCH_PASSWORD = os.getenv("ELASTICSEARCH_PASSWORD", "")
    ELASTICSEARCH_INDEX = os.getenv("ELASTICSEARCH_INDEX", "cybersentinel-events")
    KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "").strip()
    KAFKA_EVENTS_TOPIC = os.getenv("KAFKA_EVENTS_TOPIC", "cybersentinel.events")
    KAFKA_DEAD_LETTER_TOPIC = os.getenv("KAFKA_DEAD_LETTER_TOPIC", "cybersentinel.events.dlq")
    KAFKA_CONSUMER_GROUP = os.getenv("KAFKA_CONSUMER_GROUP", "cybersentinel-processors")
    KAFKA_PUBLISH_TIMEOUT_SECONDS = float(os.getenv("KAFKA_PUBLISH_TIMEOUT_SECONDS", "10"))
    KAFKA_WORKER_HEARTBEAT_SECONDS = int(os.getenv("KAFKA_WORKER_HEARTBEAT_SECONDS", "15"))
    KAFKA_MAX_HEALTHY_LAG = int(os.getenv("KAFKA_MAX_HEALTHY_LAG", "1000"))
    KAFKA_WORKER_ID = os.getenv("KAFKA_WORKER_ID", "")
    THREAT_INTEL_API_KEY = os.getenv("THREAT_INTEL_API_KEY", "")
    ENABLE_SYSLOG = os.getenv("ENABLE_SYSLOG", "false").lower() == "true"
    SYSLOG_HOST = os.getenv("SYSLOG_HOST", "127.0.0.1")
    SYSLOG_PORT = int(os.getenv("SYSLOG_PORT", "1514"))
    ML_MODEL_PATH = os.getenv("ML_MODEL_PATH", str(BASE_DIR / "app" / "ml" / "models" / "artifacts" / "isolation_forest.joblib"))
    ML_METADATA_PATH = os.getenv("ML_METADATA_PATH", str(BASE_DIR / "app" / "ml" / "models" / "artifacts" / "metadata.json"))
    RISK_THRESHOLDS = {
        "informational": int(os.getenv("RISK_INFORMATIONAL_MIN", "0")),
        "low": int(os.getenv("RISK_LOW_MIN", str(int(_RISK.get("low_max", 49)) + 1))),
        "medium": int(os.getenv("RISK_MEDIUM_MIN", str(int(_RISK.get("medium_max", 74)) + 1))),
        "high": int(os.getenv("RISK_HIGH_MIN", str(int(_RISK.get("high_max", 89)) + 1))),
        "critical": int(os.getenv("RISK_CRITICAL_MIN", str(_RISK.get("critical_min", 90)))),
    }
    AUTH_FAILURE_THRESHOLD = int(os.getenv("AUTH_FAILURE_THRESHOLD", str(_AUTH_DETECTION.get("failed_attempt_threshold", 5))))
    AUTH_WINDOW_MINUTES = int(os.getenv("AUTH_WINDOW_MINUTES", str(_AUTH_DETECTION.get("window_minutes", 10))))
    AUTH_CORRELATION_WINDOW_MINUTES = int(os.getenv("AUTH_CORRELATION_WINDOW_MINUTES", "15"))
    NETWORK_PORT_THRESHOLD = int(os.getenv("NETWORK_PORT_THRESHOLD", str(_NETWORK_DETECTION.get("distinct_destination_port_threshold", 8))))
    NETWORK_WINDOW_MINUTES = int(os.getenv("NETWORK_WINDOW_MINUTES", str(_NETWORK_DETECTION.get("window_minutes", 10))))
    ML_ANOMALY_ALERT_THRESHOLD = float(os.getenv("ML_ANOMALY_ALERT_THRESHOLD", str(_ANOMALY_DETECTION.get("alert_threshold", 0.85))))
    REPORT_MAX_RECORDS = int(os.getenv("REPORT_MAX_RECORDS", str(_CONFIG_DATA.get("reports", {}).get("maximum_records", 1000))))
    ALERT_DEDUP_MINUTES = int(os.getenv("ALERT_DEDUP_MINUTES", "30"))
