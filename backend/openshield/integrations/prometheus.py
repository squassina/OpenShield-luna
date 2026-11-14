from __future__ import annotations

import json
from typing import ClassVar
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from openshield.integrations.models import Capability, Integration


class PrometheusError(RuntimeError):
    """Credential-free Prometheus API error."""


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class PrometheusClient:
    """Read-only Prometheus HTTP API client; metrics are not ingested by OpenShield."""

    MAX_RESPONSE_BYTES = 1_048_576
    ENDPOINTS = {"/api/v1/status/runtimeinfo", "/api/v1/targets?state=active"}

    def __init__(self, base_url: str, bearer_token: str | None = None, timeout: float = 8.0):
        try:
            parsed = urlsplit(base_url)
            hostname = parsed.hostname
            if parsed.port is not None and not 1 <= parsed.port <= 65535:
                raise ValueError("Prometheus URL port is outside the valid range")
        except ValueError as exc:
            raise ValueError("Prometheus URL must be a valid absolute HTTP(S) origin") from exc
        if (
            parsed.scheme not in {"http", "https"} or not parsed.netloc or not hostname
            or parsed.path not in {"", "/"} or parsed.username or parsed.password
            or parsed.query or parsed.fragment
        ):
            raise ValueError("Prometheus URL must be an HTTP(S) origin without credentials or path")
        if bearer_token is not None and (
            not bearer_token or any(char in bearer_token for char in "\r\n")
        ):
            raise ValueError("Prometheus bearer token is invalid")
        if not 0 < timeout <= 30:
            raise ValueError("Prometheus API timeout must be between 0 and 30 seconds")
        self._base_url = base_url.rstrip("/")
        self._bearer_token = bearer_token
        self._timeout = timeout

    def _get(self, path: str) -> dict[str, object]:
        if path not in self.ENDPOINTS:
            raise ValueError("Unsupported Prometheus API operation")
        headers = {"Accept": "application/json", "User-Agent": "OpenShield/1.0"}
        if self._bearer_token:
            headers["Authorization"] = f"Bearer {self._bearer_token}"
        request = Request(self._base_url + path, headers=headers, method="GET")
        try:
            with build_opener(_NoRedirectHandler()).open(request, timeout=self._timeout) as response:
                raw = response.read(self.MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            if exc.code in {401, 403}:
                raise PrometheusError("Prometheus rejected the configured credentials or permissions") from exc
            raise PrometheusError(f"Prometheus API returned HTTP {exc.code}") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise PrometheusError("Unable to reach the Prometheus API") from exc
        if len(raw) > self.MAX_RESPONSE_BYTES:
            raise PrometheusError("Prometheus API response exceeded the size limit")
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PrometheusError("Prometheus API returned invalid JSON") from exc
        if not isinstance(payload, dict) or payload.get("status") != "success":
            raise PrometheusError("Prometheus API returned an unsuccessful or unexpected response")
        if not isinstance(payload.get("data"), dict):
            raise PrometheusError("Prometheus API returned an unexpected data envelope")
        return payload

    def diagnostics(self) -> dict[str, object]:
        runtime = self._get("/api/v1/status/runtimeinfo")
        targets = self._get("/api/v1/targets?state=active")
        active = targets["data"].get("activeTargets")
        if not isinstance(active, list):
            raise PrometheusError("Prometheus targets endpoint returned an unexpected response")
        healthy = sum(1 for target in active if isinstance(target, dict) and target.get("health") == "up")
        return {
            "runtime": runtime["data"],
            "targets": active[:100],
            "summary": {"targets_available": len(active), "targets_up": healthy,
                        "targets_down": len(active) - healthy, "targets_limit": 100},
        }


class PrometheusAdapter:
    kind = "prometheus"
    capabilities: ClassVar[list[Capability]] = [
        Capability.HEALTH_CHECK, Capability.READ_CONFIGURATION, Capability.READ_EVENTS,
    ]

    def probe(self, integration: Integration) -> dict[str, object]:
        return {
            "integration_id": integration.integration_id,
            "kind": self.kind,
            "status": "configured" if integration.config.get("auth_configured") else "needs_credentials",
            "transport": "prometheus_http_api_read_only",
            "capabilities": [item.value for item in self.capabilities],
        }
