from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class ElkService:
    def __init__(self, url: str, username: str = "", password: str = "", index: str = "cybersentinel-events"):
        self.url = url
        self.index = index
        self.client = None
        self.error: str | None = None
        if url:
            try:
                from elasticsearch import Elasticsearch

                auth = (username, password) if username else None
                self.client = Elasticsearch(url, basic_auth=auth, request_timeout=2)
            except (ImportError, ValueError) as exc:
                self.error = str(exc)
                logger.warning("Elasticsearch client initialization failed: %s", exc)
        else:
            self.error = "Elasticsearch is not configured"

    def health(self) -> str:
        if not self.client:
            return "unconfigured" if self.error == "Elasticsearch is not configured" else "unavailable"
        try:
            return "healthy" if self.client.ping() else "unavailable"
        except Exception as exc:
            logger.warning("Elasticsearch health check failed: %s", exc)
            return "unavailable"

    def index_event(self, event: dict[str, Any]) -> bool:
        if not self.client:
            return False
        try:
            self.client.index(index=self.index, document=event)
            return True
        except Exception:
            logger.exception("Event could not be indexed in Elasticsearch")
            return False

    def search(self, query: dict[str, Any], page: int = 1, per_page: int = 50) -> dict[str, Any]:
        if not self.client:
            raise RuntimeError("Elasticsearch search is unavailable")
        response = self.client.search(index=self.index, query=query, from_=(page - 1) * per_page, size=per_page)
        return {"total": response["hits"]["total"]["value"], "hits": [hit["_source"] for hit in response["hits"]["hits"]]}
