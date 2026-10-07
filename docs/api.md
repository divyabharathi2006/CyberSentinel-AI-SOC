# REST API

API errors are JSON, for example:

```json
{"success":false,"error":{"code":"INVALID_REQUEST","message":"event_type is required"}}
```

Except `/api/auth/login` and `/api/health`, authenticate with `Authorization: Bearer <access_token>`. Tokens expire after `JWT_ACCESS_TOKEN_MINUTES` (30 by default). Roles are `Admin`, `SOC Analyst`, `Security Manager`, and `Viewer`.

## Login

`POST /api/auth/login` (5 attempts/minute per remote address):

```json
{"username":"analyst","password":"your-account-password"}
```

Returns an access token and safe user profile. Sign-out writes an audit entry; clients must discard the bearer token. Access tokens are short-lived but not server-revoked before expiry.

## Event ingestion

`POST /api/events` accepts a normalized or common alias object; an array submits a batch of up to 1,000:

```json
{
  "timestamp":"2026-10-01T09:00:00Z",
  "source_ip":"198.51.100.25",
  "destination_ip":"203.0.113.20",
  "username":"synthetic-user",
  "event_type":"authentication",
  "action":"login",
  "status":"failed",
  "severity":"medium",
  "message":"Synthetic failed authentication"
}
```

Ports must be integers 1–65535; source/destination addresses must parse as IPv4/IPv6; event type is required. `timestamp` accepts ISO-8601 or Unix seconds. For batch input, HTTP 207 identifies accepted count and rejected row indices; each accepted row is persisted independently. File ingestion uses multipart field `file` and accepts `.json`, `.jsonl`, `.ndjson`, `.csv`, `.log`, and `.txt`.

When `KAFKA_BOOTSTRAP_SERVERS` is configured, REST and file-upload records return HTTP `202 Accepted` after the broker acknowledges the queue write. `accepted` and `queued` count queued records; this is not confirmation that records have been persisted or processed. Broker unavailability returns HTTP `503` and does not acknowledge the batch. Invalid rows retain their validation errors. The worker applies the same normalization, detections, ML scoring, persistence, and live updates as synchronous ingestion.

## Pipeline monitoring

Authenticated `GET /api/pipeline/status` reports broker readiness, worker heartbeat age, queue lag, processed/dead-letter counts, and the configured healthy-lag limit. `/api/health` incorporates broker and worker readiness when streaming is enabled and returns `503` when the broker or consumer pipeline is unavailable. Malformed messages go to `cybersentinel.events.dlq` with their source topic, partition, and offset.

## Search and workflow

`GET /api/events` and `GET /api/alerts` accept `page` and `per_page` (maximum 100). Events additionally accept `q`, field-specific filters, and ISO-8601 `from` / `to`. Alert `PATCH` accepts a lifecycle `status`, `assigned_to_id`, and/or a `note`. Incident create requires `title` and `description`; optional `alert_ids` must reference existing alerts. Incident update accepts status, assignment, resolution, and/or note.

`GET /api/dashboard/summary` returns counts, event/alert time series, active alert source counts, top sources/destinations/users/ports, detection categories, and model availability. `GET /api/threat-intel/<indicator>` supports IP addresses, domain names, URLs, and MD5/SHA file hashes. `GET /api/reports?type=alerts|events|incident&format=json|csv|pdf` streams an export.

The browser includes **Network Monitoring**, **Attack Timeline**, and **ML Analytics** views. File-hash detections use cached threat-intelligence matches; phishing indicators use string-only metadata checks and cached reputation. The application does not fetch or visit submitted URLs, execute files, or scan networks.

`GET /api/settings` returns the authenticated user's effective, secret-redacted runtime and detection configuration. `POST /api/demo/generate` generates and ingests synthetic lab events; it is available to Admin, SOC Analyst, and Security Manager roles, and accepts an optional `{"count": 80}` baseline count (1–900). It adds records to the database and creates normal alerts where rules match.

`GET /api/network/summary` provides bounded last-24-hour network telemetry and unresolved alert sources; it does not scan networks or infer IP reputation. `GET /api/ml/analytics` summarizes stored ML-scored alerts only, including the configured threshold and model availability. `GET /api/timeline/<incident_id>` returns the selected incident's chronological updates, notes, linked alerts, and linked events. All three endpoints require a valid bearer token.

See the route handlers under `app/api/` for exact response schemas and authorization policy. All SQL filters use the ORM; user content is not used as SQL text.
