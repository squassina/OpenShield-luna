from __future__ import annotations

import json
from typing import ClassVar
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from openshield.integrations.models import Capability, Integration


class PfSenseError(RuntimeError):
    """Credential-free pfSense API error."""


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class PfSenseClient:
    """Read-only client for the optional pfSense REST API v2 package."""

    MAX_RESPONSE_BYTES = 1_048_576

    def __init__(
        self, base_url: str, api_key: str, timeout: float = 8.0
    ) -> None:
        try:
            parsed = urlsplit(base_url)
            hostname = parsed.hostname
            if parsed.port is not None and not 1 <= parsed.port <= 65535:
                raise ValueError("pfSense URL port is outside the valid range")
        except ValueError as exc:
            raise ValueError("pfSense URL must be a valid absolute HTTP(S) origin") from exc
        if (
            parsed.scheme not in {"http", "https"} or not parsed.netloc or not hostname
            or parsed.path not in {"", "/"} or parsed.username or parsed.password
            or parsed.query or parsed.fragment
        ):
            raise ValueError("pfSense URL must be an absolute HTTP(S) origin without credentials or path")
        if not api_key or "\r" in api_key or "\n" in api_key:
            raise ValueError("pfSense API key is required")
        if not 0 < timeout <= 30:
            raise ValueError("pfSense API timeout must be between 0 and 30 seconds")
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout

    def get(self, path: str) -> dict[str, object] | list[object]:
        if (
            not path.startswith("/api/v2/") or ".." in path or "//" in path
            or "?" in path or "#" in path or "\\" in path
        ):
            raise ValueError("Invalid pfSense API path")
        request = Request(
            self._base_url + path,
            headers={
                "X-API-Key": self._api_key,
                "Accept": "application/json",
                "User-Agent": "OpenShield/1.0",
            },
        )
        try:
            opener = build_opener(_NoRedirectHandler())
            with opener.open(request, timeout=self._timeout) as response:
                raw = response.read(self.MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            if exc.code in {401, 403}:
                raise PfSenseError("pfSense rejected the API key or its permissions") from exc
            raise PfSenseError(f"pfSense API returned HTTP {exc.code}") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise PfSenseError("Unable to reach the pfSense API") from exc
        if len(raw) > self.MAX_RESPONSE_BYTES:
            raise PfSenseError("pfSense API response exceeded the size limit")
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PfSenseError("pfSense API returned invalid JSON") from exc
        if not isinstance(payload, (dict, list)):
            raise PfSenseError("pfSense API returned an unexpected response")
        return payload

    def diagnostics(self) -> dict[str, object]:
        return {
            "system": self.get("/api/v2/status/system"),
            "interfaces": self.get("/api/v2/status/interfaces"),
            "arp": self.get("/api/v2/diagnostics/arp_table"),
            "dhcp_leases": self.get("/api/v2/status/dhcp_server/leases"),
            "gateways": self.get("/api/v2/status/gateways"),
        }


class PfSenseAdapter:
    kind = "pfsense"
    capabilities: ClassVar[list[Capability]] = [
        Capability.HEALTH_CHECK,
        Capability.READ_CONFIGURATION,
        Capability.READ_EVENTS,
    ]

    def probe(self, integration: Integration) -> dict[str, object]:
        return {
            "integration_id": integration.integration_id,
            "kind": self.kind,
            "status": "configured" if integration.config.get("auth_configured") else "needs_credentials",
            "transport": "pfsense_rest_api_v2",
            "capabilities": [item.value for item in self.capabilities],
        }
