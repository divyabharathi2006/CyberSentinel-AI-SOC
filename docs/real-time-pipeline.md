# Real-time event pipeline

The Docker Compose stack routes authenticated REST events and UDP syslog messages through Apache Kafka before alert processing. External authorized producers can publish JSON directly to `cybersentinel.events`. A consumer group validates, normalizes, enriches, and persists records to PostgreSQL, then updates Elasticsearch and authenticated Socket.IO subscribers.

```text
REST API ─┐
UDP syslog ├─> Kafka: cybersentinel.events ─> event worker ─> PostgreSQL
Producers ─┘                                      ├─> detections and incidents
                                                  ├─> Elasticsearch (optional)
                                                  └─> Socket.IO live updates
Invalid records ─> Kafka: cybersentinel.events.dlq
```

Kafka is the durable ingestion buffer; PostgreSQL remains the system of record for SOC events, alerts, and incidents. Elasticsearch is optional search/indexing, not the authoritative database. SQLite mode remains available for local development and synchronous processing when `KAFKA_BOOTSTRAP_SERVERS` is unset.

## Start the local streaming stack

1. Copy `.env.example` to `.env` and replace the secret and PostgreSQL password placeholders with unique values.
2. Start the stack from PowerShell:

   ```powershell
   docker compose up --build -d
   docker compose ps
   ```

3. Seed an administrator into the PostgreSQL database using the documented environment variables in the main README.
4. Check **System Health** and **Settings → Event pipeline**. The broker and worker must report healthy before queued events can be processed.

Kafka is intentionally a single-node development broker. Its internal listener is available only to Compose services; the direct producer listener is bound to host loopback at `localhost:9094`. Do not expose this unauthenticated broker to untrusted networks. Production requires a secured managed Kafka deployment or TLS/SASL, ACLs, topic replication, monitoring, and tested recovery procedures.

## Publish an event directly to Kafka

From the host, use a Kafka client configured for `localhost:9094` and publish a UTF-8 JSON object to `cybersentinel.events`. A plain event object is accepted:

```json
{
  "event_type": "authentication",
  "source_ip": "198.51.100.25",
  "username": "lab-user",
  "status": "failed",
  "severity": "medium",
  "message": "Authorized synthetic test event"
}
```

The consumer also accepts the REST-style envelope:

```json
{
  "event": {
    "event_type": "network_connection",
    "source_ip": "198.51.100.25",
    "destination_ip": "203.0.113.10",
    "destination_port": 443,
    "protocol": "tcp",
    "severity": "informational"
  },
  "default_source": "authorized-source"
}
```

Events go through the same normalization, deterministic detections, optional ML scoring, relational persistence, and dashboard updates as existing ingestion. Invalid JSON or invalid event shapes are preserved in the dead-letter topic with their source topic, partition, and offset. Review the worker logs and DLQ before replaying corrected data.

REST event and file-upload requests return HTTP `202 Accepted` when Kafka acknowledges the batch; this means queued, not yet persisted. Events and alerts appear after the worker processes them. Without Kafka configured, existing local development endpoints retain synchronous responses.

## Monitor and scale

- `GET /api/health` includes Kafka broker and worker readiness. When streaming is enabled, unavailable Kafka or a stale worker heartbeat makes readiness fail.
- Authenticated `GET /api/pipeline/status` reports worker heartbeats, per-worker queue lag, processed counts, dead-letter counts, and the configured healthy-lag threshold.
- **System Health** displays broker/worker status and lag. **Settings** exposes the pipeline snapshot to signed-in users.
- Worker warnings and failures are emitted to container logs; invalid records are counted and forwarded to the DLQ.
- The sample topic has three partitions. To run up to three consumers in the same group, scale the Compose worker service:

  ```powershell
  docker compose up -d --scale worker=3
  ```

  Additional consumers beyond the topic partition count do not add processing parallelism. Size workers, database connections, and partitions together for production traffic.

## Backup-first data reset

No existing data is removed automatically. Stop the application and worker first to avoid new events during the reset:

```powershell
docker compose stop app worker
```

For SQLite, make a restoreable backup and clear operational tables while preserving users and the audit chain:

```powershell
python scripts\reset_database.py --backup-dir backups --confirm
```

For PostgreSQL, install `pg_dump` and ensure it can connect using the configured database URL before running the same command. The command creates a custom-format `.dump` backup first and refuses to delete data if that backup fails. Restore PostgreSQL with `pg_restore`; restore SQLite by replacing the database file while the application is stopped.

The default reset preserves user accounts and audit records. Use `--include-users --include-audit` only if you intend to reseed an administrator and discard the audit history. Both options still require a successful backup and `--confirm`. Backups may contain sensitive SOC data; store and protect them accordingly.

The database reset does not delete Kafka topic contents. If the worker is restarted while the queue still contains events, it will process those queued events into the freshly cleared database. Review/retain or deliberately purge the Kafka topics separately before restarting the worker if the intention is to remove queued telemetry too.

Restart the services after the reset:

```powershell
docker compose start postgres kafka elasticsearch
docker compose up -d kafka-init app worker
```

Do not use `docker compose down -v` as a routine reset: it deletes persistent service volumes and the Kafka queue as well as application data.
