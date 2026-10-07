# CyberSentinel AI SOC

CyberSentinel is a defensive Security Operations Center application for authorized event collection, triage, and incident tracking. It combines deterministic detections with an optional Isolation Forest anomaly signal. Neither a rule match nor an anomaly score proves malicious activity; analysts should validate each lead against trusted telemetry.

> **Use only in systems and environments you are authorized to monitor.** This project is not an exploitation, malware, credential collection, scanning, or response-automation tool.

## Features

- Flask REST API and responsive dark SOC interface
- SQLite for local development or PostgreSQL for shared deployments
- Password hashing, expiring JWTs, role authorization, login throttling, and append-only hash-chained audit records
- Validated JSON, JSON Lines, CSV, text/syslog file, and optional UDP syslog ingestion
- Normalization, brute-force / post-failure-success correlation, port fan-out, configured process indicator, and optional ML detections
- Static phishing-link indicators and cached malicious-file-hash detections; URLs are never fetched or opened
- Transparent 0–100 risk breakdown, alert and incident lifecycle, investigation evidence, and ATT&CK mappings where context supports them
- Optional direct Elasticsearch indexing, Logstash pipeline, Kibana analyst-search guidance, and authenticated Socket.IO alerts
- Kafka-backed real-time event buffering and processing in Docker Compose, with worker lag/health monitoring, a dead-letter topic, REST and UDP syslog intake, and direct Kafka producer support
- Optional VirusTotal indicator enrichment (IP, domain, file hash); unavailable enrichment does not interrupt core operations
- Dashboard, network monitoring, ML analytics, incident attack timelines, CSV/JSON/PDF exports, health checks, synthetic lab events, Docker Compose and pytest suite

## Architecture

```text
Authorized log sources
    ├── REST API / file upload / optional UDP syslog
    ↓
Validated normalization → relational event store → optional Elasticsearch indexing
    ↓                                       └── Logstash / Kibana search
Deterministic rules + optional Isolation Forest + time-window correlation
    ↓
Risk score + evidence + optional threat-intelligence enrichment
    ↓
Alerts → analyst actions → incidents → audit trail and reports
    ↓
Flask REST API + browser SOC dashboard + authenticated Socket.IO updates
```

See [docs/architecture.md](docs/architecture.md) and [docs/soc-workflow.md](docs/soc-workflow.md) for component boundaries and lifecycle details.

## Requirements

- Python 3.12 or later (the code targets 3.12+)
- Windows 10/11 with PowerShell and VS Code for direct local development
- SQLite is included with Python. PostgreSQL and ELK are optional locally and are included in the Docker Compose profile.
- Docker Desktop with Compose v2 is required only for the complete container stack. Allow several GB of available RAM; Elasticsearch alone reserves a 512 MB JVM heap and has a 1 GB container limit.

## Windows setup (SQLite)

From the project folder in PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
Copy-Item .env.example .env
```

Edit `.env` and replace both secret placeholders with different random values. For example, generate a value with:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Leave `DATABASE_URL` unset (or comment it out) for SQLite; SQLite data is written to `instance\cybersentinel.db`. The application reads `.env` automatically.

Initialize the schema and create an administrator. Flask-Migrate commands can be used after initializing the migration repository once:

```powershell
python -m flask --app run.py db init
python -m flask --app run.py db migrate -m "Initial schema"
python -m flask --app run.py db upgrade
$env:CYBERSENTINEL_ADMIN_USERNAME = "soc-admin"
$env:CYBERSENTINEL_ADMIN_EMAIL = "soc-admin@example.invalid"
$env:CYBERSENTINEL_ADMIN_PASSWORD = "Set-A-Unique-Long-Password-123"
python scripts\seed_database.py
Remove-Item Env:CYBERSENTINEL_ADMIN_PASSWORD
```

Choose a unique password that satisfies the project's minimum (12 characters, upper and lowercase letters, and a digit). No default account/password is seeded. For an isolated local development database, `python scripts\seed_database.py` creates the schema if needed.

### Run the browser demo

After signing in, open **Settings** and select **Generate and ingest demo**. Confirm the operation to add safe synthetic telemetry to the database. Review the generated records under **Events** and the detection results under **Alerts**. The default scenario includes normal baseline events, repeated failed logins, network port fan-out, and an endpoint indicator. It uses reserved example IP addresses and synthetic host/account names only.

Settings also displays the effective, secret-redacted runtime and detection configuration. Configuration values are read-only there; update `.env` or `config.yaml` and restart the app to change them.

### Generate a demo file or train ML

Generate safe synthetic telemetry as a JSONL file without ingesting it, or train the optional anomaly detector:

```powershell
python scripts\train_model.py
python scripts\generate_sample_logs.py
```

Start the app:

```powershell
python run.py
```

Open <http://127.0.0.1:5000>, sign in with the administrator account, and review **Events**, **Alerts**, **Incidents**, **Reports**, and **System Health**. To generate and immediately ingest the synthetic records, first sign in through the API and set the returned access token in the environment:

```powershell
$login = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:5000/api/auth/login -ContentType "application/json" -Body '{"username":"soc-admin","password":"YOUR_PASSWORD"}'
$env:CYBERSENTINEL_TOKEN = $login.access_token
python scripts\generate_sample_logs.py --ingest-url http://127.0.0.1:5000
Remove-Item Env:CYBERSENTINEL_TOKEN
```

The generated events use RFC-reserved example IP address ranges and synthetic account/host names; they do not represent real people or systems.

## Docker Compose (PostgreSQL + ELK)

1. Copy `.env.example` to `.env`.
2. Replace all secret and PostgreSQL password placeholders. For Compose, keep the `DATABASE_URL` setting in `.env`; Compose overrides its host to the PostgreSQL service.
3. From PowerShell, start all services:

```powershell
docker compose up --build -d
docker compose ps
```

Open the app at <http://localhost:5000>, Elasticsearch at <http://localhost:9200>, and Kibana at <http://localhost:5601>. PostgreSQL is published only on loopback at `localhost:5432` so the host can run the account seeding script using the `DATABASE_URL` in `.env`. The Compose stack also includes Kafka at `localhost:9094` for authorized direct producers and a worker service. UDP syslog listens on loopback port `1514`:

```powershell
$env:CYBERSENTINEL_ADMIN_USERNAME = "soc-admin"
$env:CYBERSENTINEL_ADMIN_EMAIL = "soc-admin@example.invalid"
$env:CYBERSENTINEL_ADMIN_PASSWORD = "Set-A-Unique-Long-Password-123"
python scripts\seed_database.py
Remove-Item Env:CYBERSENTINEL_ADMIN_PASSWORD
```

Train a model inside the container with `docker compose exec app python scripts/train_model.py`. To follow service logs, use `docker compose logs -f app worker kafka elasticsearch logstash kibana`. Stop without deleting persistent state with `docker compose down`. `docker compose down -v` deletes database, Kafka, and Elasticsearch volumes and should only be used when intentionally discarding lab data.

REST event and file-upload endpoints acknowledge Kafka-backed batches with HTTP `202 Accepted`; records then appear in the UI as the worker processes them. Monitor **System Health**, **Settings → Event pipeline**, or authenticated `GET /api/pipeline/status` for worker heartbeat and consumer lag. Invalid records are retained on the `cybersentinel.events.dlq` topic. See [docs/real-time-pipeline.md](docs/real-time-pipeline.md) for direct Kafka message formats, scaling notes, and the backup-first reset procedure. The reset command is not run automatically and preserves user accounts and audit records unless explicitly instructed otherwise.

The Compose ELK environment is intentionally loopback-bound and disables Elasticsearch security to keep the lab lightweight. Do not expose it to untrusted networks or deploy it as production infrastructure. Production must configure TLS, authenticated ELK access, secret management, network policy, backups, and resource sizing.

## Configuration

See [.env.example](.env.example). Important settings:

| Variable | Purpose |
| --- | --- |
| `SECRET_KEY`, `JWT_SECRET_KEY` | Separate high-entropy application/JWT signing secrets; required in production |
| `DATABASE_URL` | SQLAlchemy URL (`sqlite:///...` or `postgresql+psycopg://...`) |
| `ELASTICSEARCH_URL`, `ELASTICSEARCH_USERNAME`, `ELASTICSEARCH_PASSWORD` | Optional Elasticsearch target and credentials |
| `ELASTICSEARCH_INDEX` | Event index name |
| `KAFKA_BOOTSTRAP_SERVERS` | Optional Kafka broker list. Compose configures its internal broker automatically; unset means synchronous local ingestion |
| `KAFKA_EVENTS_TOPIC`, `KAFKA_DEAD_LETTER_TOPIC`, `KAFKA_CONSUMER_GROUP` | Ingestion, invalid-record, and consumer-group names |
| `KAFKA_WORKER_HEARTBEAT_SECONDS`, `KAFKA_MAX_HEALTHY_LAG` | Worker health and queue-lag readiness thresholds |
| `THREAT_INTEL_API_KEY` | Optional VirusTotal API key; never needed for local operation |
| `JWT_ACCESS_TOKEN_MINUTES` | Bearer token lifetime (default 30 minutes) |
| `MAX_CONTENT_LENGTH` | Request body limit in bytes (default 1 MiB) |
| `ENABLE_SYSLOG`, `SYSLOG_HOST`, `SYSLOG_PORT` | Opt-in UDP syslog receiver; binds loopback by default |
| `CORS_ORIGINS` | Explicit comma-separated browser origins; empty means same-origin only |

Do not commit `.env`, database files, model artifacts, or credentials.

## API overview

All API routes use JSON error objects (`success: false`, `error.code`, and `error.message`) where applicable. Except for login and health, APIs require an `Authorization: Bearer <token>` header. Analysts and security managers have write access to operational workflows; only Admin can create users.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `POST` | `/api/auth/login` | Authenticate, receive expiring bearer token |
| `POST` | `/api/auth/logout` | Record sign-out; client discards token |
| `GET` | `/api/auth/me` | Current user and role |
| `GET`, `POST` | `/api/events` | Search / ingest one or a batch of events |
| `GET` | `/api/events/<id>` | Full normalized event |
| `POST` | `/api/events/upload` | Upload JSON, JSONL, CSV, LOG, or TXT |
| `GET`, `PATCH` | `/api/alerts`, `/api/alerts/<id>` | Search, inspect, assign, annotate, and update status |
| `POST` | `/api/alerts/<id>/incidents` | Create an incident linked to an alert |
| `GET`, `POST` | `/api/incidents` | Search / create incidents |
| `GET`, `PATCH` | `/api/incidents/<id>` | Inspect / update incident state and notes |
| `GET` | `/api/dashboard/summary` | SOC counts, top sources, and trend series |
| `GET` | `/api/threat-intel/<indicator>` | Cached/provider indicator enrichment |
| `GET` | `/api/reports?type=alerts&format=json` | Download alerts, events, or incident report as JSON, CSV, or PDF |
| `GET` | `/api/users` | List users (Admin / Security Manager) |
| `POST` | `/api/users` | Create user (Admin only) |
| `GET` | `/api/audit-logs` | Read audit records (Admin / Security Manager) |
| `GET` | `/api/health` | Application, DB, ELK, model, and listener health |
| `GET` | `/api/pipeline/status` | Authenticated Kafka broker/worker heartbeat, lag, and processing metrics |

Event search supports pagination plus `q`, `source_ip`, `destination_ip`, `username`, `hostname`, `event_type`, `severity`, `process`, `from`, and `to` query parameters. See [docs/api.md](docs/api.md) for request examples.

## ML and detections

`python scripts/train_model.py` trains a real scikit-learn `IsolationForest` using engineered, validated numeric features. Without a dataset it trains on deterministic synthetic baseline events; `--dataset path.csv` accepts an analyst-provided CSV containing at least `event_type` plus supported event fields. It saves a versioned joblib artifact and metadata under `app/ml/models/artifacts/` and records model metadata in the relational store. Artifacts are ignored by Git; train separately in each deployment environment and protect them as operational data.

The ML pipeline's synthetic holdout probe is a smoke test, not an efficacy or accuracy claim. No supervised classifier is trained without labeled data. Missing/incompatible model artifacts are reported as unavailable; deterministic detections continue. The feature schema and anomaly threshold are documented in [docs/ml.md](docs/ml.md).

## Tests and quality

```powershell
pytest
ruff check app scripts tests
python -m compileall -q app scripts tests run.py
```

Test suite covers authentication and RBAC, normalization and ingestion, detections, risk scoring, model fallback/features, incidents, threat indicator validation, reports, and audit-chain integrity. Elasticsearch and provider network calls are optional and are not mocked as successful in production paths.

## Limitations and operational notes

- The app has no default user, database migration, threat feed, or trained model artifact. Create the admin, apply migrations, and train the model explicitly.
- Rule thresholds and process indicators are demonstrative starting points. Tune them against authorized environment baselines and validate false-positive/false-negative behavior before operational use.
- Geolocation/impossible-travel analytics, generic URL/hash scanning, asset inventory UI, alert retention, and automated response are not implemented. No response action is run against endpoints or accounts.
- The sample dashboard computes common counts and 24-hour event trends from SQL; large enterprise telemetry volumes should use background aggregation and Elasticsearch-backed analytics.
- HTTP/UDP syslog and external enrichment are optional. Enrichment depends on provider connectivity and policy approval; absence of a result is not evidence of a clean indicator.
- Socket.IO updates use short-lived JWTs and are designed for a single application process; multi-worker production deployments need a shared Socket.IO message queue and token revocation strategy.
- The current audit chain detects changes to ordered audit rows but is not externally anchored, immutable storage; a privileged database administrator can rewrite the entire chain.
- PostgreSQL and Elasticsearch downtime is reflected in health/status; relational DB is required for core API storage. In Kafka-enabled mode, broker and consumer-worker availability are also required for ready event ingestion. ML and threat intelligence remain optional.

## Troubleshooting

- **`SECRET_KEY and JWT_SECRET_KEY must be configured in production`**: set different random values in `.env` and restart.
- **Login returns invalid credentials**: create an administrator with the documented environment-based seed script; no demo account exists.
- **ML unavailable**: run `python scripts/train_model.py`, check that `metadata.json` and the `.joblib` model exist, and verify feature version `1`.
- **Elasticsearch unavailable**: the app keeps events in SQL and reports ELK as unavailable. Check `docker compose logs elasticsearch`, available RAM, and the `ELASTICSEARCH_URL`.
- **Database health is unavailable**: verify `DATABASE_URL`, PostgreSQL credentials, service health, and migrations. SQLite local mode requires write permission for `instance\`.
- **Compose cannot start Elasticsearch**: allocate sufficient Docker Desktop memory, wait for its health check, and avoid using this single-node development stack for a production workload.
