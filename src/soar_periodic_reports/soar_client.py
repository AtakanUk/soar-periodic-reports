"""IBM SOAR REST queries used by the reports."""

from __future__ import annotations

import logging
from typing import Any, Protocol

from .config import SoarSettings

log = logging.getLogger(__name__)

QUERY_PAGED_URI = "/incidents/query_paged?return_level=full"


class RestClient(Protocol):
    def get(self, uri: str) -> Any: ...

    def post(self, uri: str, payload: Any) -> Any: ...


class SoarClient:
    def __init__(
        self, rest_client: RestClient, page_size: int = 1000, max_results: int = 50_000
    ) -> None:
        self._client = rest_client
        self._page_size = page_size
        self._max_results = max_results

    @classmethod
    def connect(cls, settings: SoarSettings) -> SoarClient:
        import resilient

        return cls(resilient.get_client(settings.client_options()))

    def incidents_created_between(
        self, start_ms: int, end_ms: int, extra_conditions: list[dict[str, Any]] | None = None
    ) -> list[dict[str, Any]]:
        conditions = [
            {"field_name": "create_date", "method": "gte", "value": start_ms},
            {"field_name": "create_date", "method": "lte", "value": end_ms},
            *(extra_conditions or []),
        ]
        query: dict[str, Any] = {
            "filters": [{"conditions": conditions}],
            "sorts": [{"field_name": "create_date", "type": "asc"}],
            "start": 0,
            "length": self._page_size,
        }
        incidents: list[dict[str, Any]] = []
        while True:
            query["start"] = len(incidents)
            page = (self._client.post(QUERY_PAGED_URI, query) or {}).get("data") or []
            incidents.extend(page)
            if len(page) < self._page_size:
                break
            if len(incidents) >= self._max_results:
                log.warning("Stopped paging after %d incidents (max_results)", len(incidents))
                break
        log.debug("Fetched %d incidents between %d and %d", len(incidents), start_ms, end_ms)
        return incidents

    def field_labels(self, field_name: str) -> dict[Any, str]:
        """Map the stored values of a select field to their display labels."""
        definition = self._client.get(f"/types/incident/fields/{field_name}") or {}
        return {item.get("value"): item.get("label") for item in definition.get("values") or []}

    def create_incident(self, incident: dict[str, Any]) -> dict[str, Any]:
        return self._client.post("/incidents", incident)
