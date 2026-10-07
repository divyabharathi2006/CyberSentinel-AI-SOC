# Architecture

## Components and data flow

1. **Ingestion** accepts a single event/batch over REST, a bounded structured file upload, an opt-in UDP syslog record, or direct authorized Kafka producer messages.
2. **Queueing** sends normalized REST and file-upload records to the configured Kafka topic when streaming is enabled. Kafka buffers records independently of the web request. SQLite development mode without Kafka retains the synchronous ingestion path.
3. **Processing** a consumer-group worker validates direct Kafka messages, runs the same normalization, deterministic and ML detections, and records invalid messages in a dead-letter topic. Database checkpoints and disabled Kafka auto-commit support replay-safe event persistence.
4. **Persistence** stores processed events, alerts, incidents, and worker metrics in PostgreSQL for the Compose streaming stack or SQLite in local mode. SQL indexes support timestamp, severity, source, destination, and user investigations.
5. **Search integration** attempts direct Elasticsearch indexing after relational commit. An unavailable cluster is logged and reported in health status; it does not block SQL storage. Logstash accepts JSON HTTP/Beats records and Kibana provides an optional analyst query experience.
5. **Detections** run deterministic authentication, network, endpoint-indicator, and time-window correlation logic. If a compatible trained Isolation Forest is present, a model signal can also raise an explicitly advisory anomaly alert.
6. **Risk** combines documented rule severity, anomaly, event frequency, criticality, threat confidence, and correlation factors into a capped 0–100 score with an inspectable breakdown.
7. **Response workflow** stores alerts and their exact evidence links; analysts acknowledge, assign, investigate, escalate, resolve, mark false positive, add notes, and create linked incidents.
8. **Presentation** uses a same-origin Flask REST API, Jinja-rendered pages, accessible HTML tables, Chart.js charts, and JWT-authenticated Socket.IO updates. Pipeline status exposes broker health, consumer heartbeats, and lag.

## Trust boundaries

- User-controlled input is validated before ORM persistence; SQLAlchemy parameters handle query binding. Uploaded files are read as data only, bounded by the HTTP request limit and 1,000-record cap, and never written to user-specified paths.
- JWTs are short-lived and carried in an authorization header. Passwords are one-way hashed. CSRF is not applicable to the bearer-only API design; session cookies are not used.
- Secrets, provider keys, and ELK credentials come from environment variables. Production startup rejects missing signing secrets.
- Third-party indicator lookups are opt-in and disclose the indicator to the configured provider. Failure, unconfigured provider, and no result remain distinct from a clean reputation.
- The local Compose stack is for a loopback-bound development lab only. It disables Elasticsearch security and is not a production deployment template.
- Compose Kafka is a single-node development broker with plaintext listeners. Production must configure authenticated encryption, ACLs, replication, monitored capacity, and restore/replay procedures.

## Database entities

`User`, `Event`, `Alert`, `AlertEvent`, `Incident`, `IncidentAlert`, `Asset`, `ThreatIntelligence`, `AuditLog`, `ModelVersion`, `KafkaPartitionCheckpoint`, and `KafkaWorkerStatus`. The normalized event records are independent of Elasticsearch availability; alerts point to evidence through join rows and incidents point to alerts.

## Availability

PostgreSQL/SQLite is required to persist events and operations. In Kafka-enabled mode, Kafka and at least one fresh worker heartbeat under the configured lag limit are required for ingestion readiness. Elasticsearch, a model artifact, VirusTotal, and syslog are otherwise optional. If the relational database is unavailable, core data API operations fail with a controlled 503 response.
