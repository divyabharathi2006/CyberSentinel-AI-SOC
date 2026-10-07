# SOC analyst workflow

1. **Collect** authorized application, authentication, network, or endpoint telemetry over REST, file import, optional UDP syslog, or direct Kafka producers.
2. **Buffer** records durably on Kafka when streaming mode is enabled. REST/file APIs return `202 Accepted` once queued; check pipeline health and lag while the consumer processes the records.
3. **Validate and normalize** events into shared fields; malformed Kafka rows are sent to the dead-letter topic and malformed synchronous input is rejected explicitly. Telemetry is processed as data and does not execute as code.
4. **Detect** repeated login failures, a success after multiple failures, destination-port fan-out, configured endpoint indicators, and optional ML anomalies. Rule evidence identifies the linked event IDs and reason; detections are leads, not conclusions.
5. **Triage** the dashboard and alert queue by risk, severity, and state. Inspect exact event evidence, score breakdown, rule explanation, optional threat enrichment, and ATT&CK rationale.
6. **Record analyst action** by acknowledging, assigning, investigating, escalating, resolving, or marking a false positive. Notes and changes produce audit entries.
7. **Create an incident** from an alert or use the incident form to link multiple signals; update ownership, status, notes, and resolution.
8. **Report** alerts, events, or incidents as JSON, CSV, or PDF. Monitor relational DB, Kafka broker/worker heartbeats and lag, Elasticsearch, model, and ingestion health.

## Status lifecycle

- Alert: `NEW` → `ACKNOWLEDGED` → `INVESTIGATING` → `ESCALATED`, `RESOLVED`, or `FALSE_POSITIVE`.
- Incident: `Open` → `Investigating` → `Contained` → `Resolved` → `Closed`.

The UI and API permit analyst updates while preserving audit history. No automatic blocking, isolation, process termination, or account lockout is performed.
