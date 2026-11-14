from __future__ import annotations

import json
from typing import ClassVar
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from openshield.integrations.models import Capability, Integration


class CrowdSecError(RuntimeError):
    """Credential-free CrowdSec Local API error."""


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class CrowdSecClient:
    """Read-only CrowdSec LAPI client; only the login endpoint uses POST."""

    MAX_RESPONSE_BYTES = 1_048_576
    ALERTS_LIMIT = 100

    def __init__(
        self,
        base_url: str,
        bouncer_api_key: str,
        machine_id: str | None = None,
        machine_password: str | None = None,
        timeout: float = 8.0,
    ) -> None:
        try:
            parsed = urlsplit(base_url)
            hostname = parsed.hostname
            if parsed.port is not None and not 1 <= parsed.port <= 65535:
                raise ValueError("CrowdSec URL port is outside the valid range")
        except ValueError as exc:
            raise ValueError("CrowdSec URL must be a valid absolute HTTP(S) origin") from exc
        if (
            parsed.scheme not in {"http", "https"} or not parsed.netloc or not hostname
            or parsed.path not in {"", "/"} or parsed.username or parsed.password
            or parsed.query or parsed.fragment
        ):
            raise ValueError("CrowdSec URL must be an absolute HTTP(S) origin without credentials or path")
        if not bouncer_api_key or "\r" in bouncer_api_key or "\n" in bouncer_api_key:
            raise ValueError("CrowdSec bouncer API key is required")
        if bool(machine_id) != bool(machine_password):
            raise ValueError("CrowdSec machine ID and password must be supplied together")
        if machine_id and ("\r" in machine_id or "\n" in machine_id):
            raise ValueError("CrowdSec machine ID contains invalid characters")
        if not 0 < timeout <= 30:
            raise ValueError("CrowdSec API timeout must be between 0 and 30 seconds")
        self._base_url = base_url.rstrip("/")
        self._bouncer_api_key = bouncer_api_key
        self._machine_id = machine_id
        self._machine_password = machine_password
        self._timeout = timeout

    def _request(
        self, path: str, method: str, headers: dict[str, str], body: bytes | None = None
    ) -> dict[str, object] | list[object]:
        allowed = {
            ("/v1/watchers/login", "POST"),
            ("/v1/alerts?limit=100", "GET"),
            ("/v1/decisions", "GET"),
        }
        if (path, method) not in allowed:
            raise ValueError("Unsupported CrowdSec API operation")
        request = Request(
            self._base_url + path,
            data=body,
            headers={**headers, "Accept": "application/json", "User-Agent": "OpenShield/1.0"},
            method=method,
        )
        try:
            opener = build_opener(_NoRedirectHandler())
            with opener.open(request, timeout=self._timeout) as response:
                raw = response.read(self.MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            if exc.code in {401, 403}:
                raise CrowdSecError("CrowdSec rejected the configured credentials or permissions") from exc
            raise CrowdSecError(f"CrowdSec Local API returned HTTP {exc.code}") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise CrowdSecError("Unable to reach the CrowdSec Local API") from exc
        if len(raw) > self.MAX_RESPONSE_BYTES:
            raise CrowdSecError("CrowdSec Local API response exceeded the size limit")
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CrowdSecError("CrowdSec Local API returned invalid JSON") from exc
        if not isinstance(payload, (dict, list)):
            raise CrowdSecError("CrowdSec Local API returned an unexpected response")
        return payload

    def _login(self) -> str:
        if not self._machine_id or not self._machine_password:
            raise ValueError("CrowdSec machine credentials are not configured")
        payload = self._request(
            "/v1/watchers/login",
            "POST",
            {"Content-Type": "application/json"},
            json.dumps({
                "machine_id": self._machine_id,
                "password": self._machine_password,
            }).encode("utf-8"),
        )
        token = payload.get("token") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token:
            raise CrowdSecError("CrowdSec Local API login returned no session token")
        return token

    def diagnostics(self) -> dict[str, object]:
        alerts = None
        if self._machine_id and self._machine_password:
            token = self._login()
            alerts_payload = self._request(
                f"/v1/alerts?limit={self.ALERTS_LIMIT}",
                "GET",
                {"Authorization": f"Bearer {token}"},
            )
            if not isinstance(alerts_payload, list):
                raise CrowdSecError("CrowdSec alerts endpoint returned an unexpected response")
            alerts = alerts_payload
        decisions_payload = self._request(
            "/v1/decisions",
            "GET",
            {"X-Api-Key": self._bouncer_api_key},
        )
        if not isinstance(decisions_payload, list):
            raise CrowdSecError("CrowdSec decisions endpoint returned an unexpected response")
        return {
            "alerts": alerts,
            "decisions": decisions_payload,
            "summary": {
                "alerts_available": len(alerts) if alerts is not None else None,
                "decisions_available": len(decisions_payload),
                "alerts_auth_configured": alerts is not None,
            },
        }


class CrowdSecAdapter:
    kind = "crowdsec"
    capabilities: ClassVar[list[Capability]] = [
        Capability.HEALTH_CHECK,
        Capability.READ_EVENTS,
    ]

    def probe(self, integration: Integration) -> dict[str, object]:
        return {
            "integration_id": integration.integration_id,
            "kind": self.kind,
            "status": "configured" if integration.config.get("auth_configured") else "needs_credentials",
            "transport": "crowdsec_local_api",
            "capabilities": [item.value for item in self.capabilities],
        }
