from __future__ import annotations

import logging
import socketserver
import threading

from app.services.log_normalizer import parse_syslog_line

logger = logging.getLogger(__name__)


class _SyslogHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        raw = self.request[0].decode("utf-8", errors="replace") if isinstance(self.request, tuple) else self.request.recv(8192).decode("utf-8", errors="replace")
        line = raw.strip()
        if not line or len(line) > 8192:
            return
        app = self.server.application
        from app.services.kafka_pipeline import publish_events
        from app.services.log_ingestion import ingest_one
        from app.services.log_normalizer import normalize_event

        with app.app_context():
            try:
                payload = parse_syslog_line(line)
                if app.config["KAFKA_BOOTSTRAP_SERVERS"]:
                    publish_events(
                        [(normalize_event(payload, default_source="syslog"), "syslog")],
                        actor_id=None,
                    )
                else:
                    ingest_one(payload, actor_id=None, default_source="syslog")
            except Exception:
                logger.exception("Received syslog record could not be ingested")


class _ThreadedUDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class _ThreadedTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_syslog_listener(app) -> None:
    host = app.config["SYSLOG_HOST"]
    port = app.config["SYSLOG_PORT"]
    try:
        server = _ThreadedUDPServer((host, port), _SyslogHandler)
        server.application = app
        threading.Thread(target=server.serve_forever, name="cybersentinel-syslog", daemon=True).start()
        app.extensions["syslog_server"] = server
        app.logger.info("UDP syslog listener started on %s:%s", host, port)
    except OSError:
        app.logger.exception("Could not start configured UDP syslog listener on %s:%s", host, port)
