from __future__ import annotations

import base64
import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from typing import ClassVar

from openshield.integrations.models import Capability, Integration


class OPNsenseError(RuntimeError):
    """Credential-free OPNsense API error."""


class OPNsenseClient:
    """Read-only OPNsense API client. Only GET endpoints are exposed."""

    def __init__(
        self, base_url: str, api_key: str, api_secret: str, timeout: float = 8.0
    ) -> None:
        parsed = urlsplit(base_url)
        if (
            parsed.scheme not in {"http", "https"} or not parsed.netloc
            or parsed.username or parsed.password or parsed.query or parsed.fragment
        ):
            raise ValueError("OPNsense URL must be an absolute HTTP(S) URL without credentials")
        if not api_key or not api_secret:
            raise ValueError("OPNsense API key and secret are required")
        if not 0 < timeout <= 30:
            raise ValueError("OPNsense API timeout must be between 0 and 30 seconds")
        self._base_url = base_url.rstrip("/")
        token = base64.b64encode(f"{api_key}:{api_secret}".encode()).decode("ascii")
        self._authorization = f"Basic {token}"
        self._timeout = timeout

    def get(self, path: str) -> dict[str, object]:
        if not path.startswith("/api/") or ".." in path:
            raise ValueError("Invalid OPNsense API path")
        request = Request(
            self._base_url + path,
            headers={
                "Authorization": self._authorization,
                "Accept": "application/json",
                "User-Agent": "OpenShield/1.0",
            },
        )
        try:
            with urlopen(request, timeout=self._timeout) as response:
                raw = response.read(1_048_577)
        except HTTPError as exc:
            if exc.code in {401, 403}:
                raise OPNsenseError("OPNsense rejected the API credentials or permissions") from exc
            raise OPNsenseError(f"OPNsense API returned HTTP {exc.code}") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise OPNsenseError("Unable to reach the OPNsense API") from exc
        if len(raw) > 1_048_576:
            raise OPNsenseError("OPNsense API response exceeded the size limit")
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OPNsenseError("OPNsense API returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise OPNsenseError("OPNsense API returned an unexpected response")
        return payload

    def diagnostics(self) -> dict[str, object]:
        return {
            "system": self.get("/api/diagnostics/system/system_information"),
            "firewall": self.get("/api/diagnostics/firewall/stats"),
            "arp": self.get("/api/diagnostics/interface/get_arp"),
        }


class OPNsenseAdapter:
    kind = "opnsense"
    capabilities: ClassVar[list[Capability]] = [
        Capability.HEALTH_CHECK,
        Capability.READ_CONFIGURATION,
        Capability.READ_EVENTS,
    ]

    def probe(self, integration: Integration) -> dict[str, object]:
        return {
            "integration_id": integration.integration_id,
            "kind": self.kind,
            "status": "configured" if integration.config.get("credentials_configured") else "needs_credentials",
            "transport": "opnsense_rest_api",
            "capabilities": [item.value for item in self.capabilities],
        }
