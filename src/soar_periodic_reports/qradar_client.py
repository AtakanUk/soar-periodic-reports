"""Minimal QRadar REST client for log source health checks."""

from __future__ import annotations

from typing import Any

import requests

from .config import QRadarSettings

LOG_SOURCES_PATH = "/api/config/event_sources/log_source_management/log_sources"
LOG_SOURCE_TYPES_PATH = "/api/config/event_sources/log_source_management/log_source_types"


class QRadarClient:
    def __init__(
        self, settings: QRadarSettings, session: requests.Session | None = None, timeout: int = 60
    ) -> None:
        self._base_url = f"https://{settings.host}"
        self._timeout = timeout
        self._session = session or requests.Session()
        self._session.verify = settings.verify
        self._session.headers.update(
            {"SEC": settings.token, "Version": settings.api_version, "Accept": "application/json"}
        )

    def _get(self, path: str, params: dict[str, str] | None = None) -> Any:
        response = self._session.get(self._base_url + path, params=params, timeout=self._timeout)
        response.raise_for_status()
        return response.json()

    def log_sources_in_error(self) -> list[dict[str, Any]]:
        return self._get(
            LOG_SOURCES_PATH,
            params={
                "filter": 'status/status="ERROR"',
                "fields": "id,name,type_id,enabled,status(status),last_event_time,group_ids",
            },
        )

    def log_source_type_names(self) -> dict[int, str]:
        types = self._get(LOG_SOURCE_TYPES_PATH, params={"fields": "id,name"})
        return {item["id"]: item["name"] for item in types}
