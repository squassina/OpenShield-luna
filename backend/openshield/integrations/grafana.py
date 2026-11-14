from __future__ import annotations

import json
from typing import ClassVar
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from openshield.integrations.models import Capability, Integration


class GrafanaError(RuntimeError):
    """Credential-free Grafana API error."""


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GrafanaClient:
    """Read-only Grafana HTTP API client for health and dashboard metadata."""

    MAX_RESPONSE_BYTES = 1_048_576
    ENDPOINTS: ClassVar[set[str]] = {
        "/api/health",
        "/api/search/?type=dash-db&limit=100",
    }

    def __init__(self, base_url: str, bearer_token: str | None = None, timeout: float = 8.0):
        try:
            parsed = urlsplit(base_url)
            hostname = parsed.hostname
            if parsed.port is not None and not 1 <= parsed.port <= 65535:
                raise ValueError("Grafana URL port is outside the valid range")
        except ValueError as exc:
            raise ValueError("Grafana URL must be a valid absolute HTTP(S) origin") from exc
        if (
            parsed.scheme not in {"http", "https"} or not parsed.netloc or not hostname
            or parsed.path not in {"", "/"} or parsed.username or parsed.password
            or parsed.query or parsed.fragment
        ):
            raise ValueError("Grafana URL must be an HTTP(S) origin without credentials or path")
        if bearer_token is not None and (
            not bearer_token or any(char in bearer_token for char in "\r\n")
        ):
            raise ValueError("Grafana bearer token is invalid")
        if not 0 < timeout <= 30:
            raise ValueError("Grafana API timeout must be between 0 and 30 seconds")
        self._base_url = base_url.rstrip("/")
        self._bearer_token = bearer_token
        self._timeout = timeout

    def _get(self, path: str) -> object:
        if path not in self.ENDPOINTS:
            raise ValueError("Unsupported Grafana API operation")
        headers = {"Accept": "application/json", "User-Agent": "OpenShield/1.0"}
        if self._bearer_token:
            headers["Authorization"] = f"Bearer {self._bearer_token}"
        request = Request(self._base_url + path, headers=headers, method="GET")
        try:
            opener = build_opener(_NoRedirectHandler())
            with opener.open(request, timeout=self._timeout) as response:
                raw = response.read(self.MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            if exc.code in {401, 403}:
                raise GrafanaError(
                    "Grafana rejected the configured credentials or permissions"
                ) from exc
            raise GrafanaError(f"Grafana API returned HTTP {exc.code}") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise GrafanaError("Unable to reach the Grafana API") from exc
        if len(raw) > self.MAX_RESPONSE_BYTES:
            raise GrafanaError("Grafana API response exceeded the size limit")
        try:
            return json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GrafanaError("Grafana API returned invalid JSON") from exc

    def diagnostics(self) -> dict[str, object]:
        health = self._get("/api/health")
        dashboards = self._get("/api/search/?type=dash-db&limit=100")
        if (
            not isinstance(health, dict)
            or not isinstance(health.get("database"), str)
            or not isinstance(health.get("version"), str)
        ):
            raise GrafanaError("Grafana health endpoint returned an unexpected response")
        if not isinstance(dashboards, list) or any(
            not isinstance(item, dict)
            or not isinstance(item.get("uid"), str)
            or not isinstance(item.get("title"), str)
            or item.get("type") != "dash-db"
            for item in dashboards
        ):
            raise GrafanaError("Grafana search endpoint returned an unexpected response")
        safe_dashboards = [
            {
                key: item[key]
                for key in ("uid", "title", "url", "folderTitle", "folderUid", "tags")
                if key in item and isinstance(item[key], (str, list))
            }
            for item in dashboards[:100]
        ]
        return {
            "health": {
                "database": health["database"],
                "version": health["version"],
                "commit": health.get("commit"),
            },
            "dashboards": safe_dashboards,
            "summary": {"dashboards_returned": len(dashboards), "dashboards_limit": 100},
        }


class GrafanaAdapter:
    kind = "grafana"
    capabilities: ClassVar[list[Capability]] = [
        Capability.HEALTH_CHECK, Capability.READ_CONFIGURATION,
    ]

    def probe(self, integration: Integration) -> dict[str, object]:
        return {
            "integration_id": integration.integration_id,
            "kind": self.kind,
            "status": (
                "configured" if integration.config.get("auth_configured") else "needs_credentials"
            ),
            "transport": "grafana_http_api_read_only",
            "capabilities": [item.value for item in self.capabilities],
        }
