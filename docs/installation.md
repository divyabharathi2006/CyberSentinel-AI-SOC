# Installation and operations

See the README for complete Windows PowerShell and Compose commands.

## Windows local sequence

1. Install Python 3.12+, create `.venv`, activate it, and install `requirements-dev.txt`.
2. Copy `.env.example` to `.env`; change both application secrets. Use SQLite for initial setup.
3. Initialize/upgrade the Flask-Migrate database schema.
4. Set `CYBERSENTINEL_ADMIN_USERNAME`, `CYBERSENTINEL_ADMIN_EMAIL`, and `CYBERSENTINEL_ADMIN_PASSWORD`, run `python scripts/seed_database.py`, and clear the password environment variable.
5. Run `python scripts/train_model.py` if anomaly scoring is wanted.
6. Run `python run.py`. The local development server binds to `127.0.0.1:5000` by default.
7. Sign in and ingest a synthetic file or generate and post records using the optional `--ingest-url` parameter.

## Generate a browser demo

After signing in, open **Settings** and choose **Generate and ingest demo**. Confirm the action; it adds synthetic events to the configured database and processes them through normal detections. Follow **View events** and **Review alerts** to explore the results. The action is available only to Admin, SOC Analyst, and Security Manager roles. Generated records use reserved example IP ranges and should be treated as demo data; clean up the local database only when intentionally discarding all local records.

To generate a file without ingesting it, run `python scripts/generate_sample_logs.py`. The default output is `data/sample_logs/synthetic_events.jsonl`; pass `--count 1` through `--count 900` to change the number of baseline records. For the browser workflow, no token or command-line setup is needed.

## Docker sequence

Copy `.env.example` to `.env`; replace each placeholder with unique secrets; then `docker compose up --build -d`. The app listens at localhost:5000, Kibana at localhost:5601, Elasticsearch at localhost:9200, and PostgreSQL remains internal to the Compose network. The app waits for PostgreSQL health; it tolerates an unavailable Elasticsearch cluster.

## Schema changes

For the initial migration repository, run `python -m flask --app run.py db init`, then `db migrate -m "Initial schema"` and `db upgrade`. For later model changes, generate and review a new migration, then run `db upgrade`. Do not call `db.create_all()` in deployed production environments as a substitute for reviewed migrations.

## Resource / secret handling

The Compose ELK services use bounded container memory, but a developer workstation should still provide several GB for all containers. PostgreSQL and Elasticsearch data live in named volumes. Do not put real keys or passwords in source control, command transcripts, test fixtures, or logs. Use a managed secrets store and TLS for production.
