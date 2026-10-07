from __future__ import annotations

import logging

from app import create_app
from app.services.kafka_worker import EventWorker


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    app = create_app()
    if not app.config["KAFKA_BOOTSTRAP_SERVERS"]:
        raise RuntimeError("KAFKA_BOOTSTRAP_SERVERS must be set to run the event worker")
    worker = EventWorker(app)
    try:
        worker.run()
    finally:
        worker.close()


if __name__ == "__main__":
    main()
