from __future__ import annotations

import base64
import json
from typing import ClassVar
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from openshield.integrations.models import Capability, Integration


class WazuhError(RuntimeError):
    """Credential-free Wazuh Server API error."""


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class WazuhClient:
    """Read-only Wazuh Server API client."""

    MAX_RESPONSE_BYTES = 1_048_576
    AGENTS_LIMIT = 500

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        timeout: float = 8.0,
    ) -> None:
        try:
            parsed = urlsplit(base_url)
            hostname = parsed.hostname
            if parsed.port is not None and not 1 <= parsed.port <= 65535:
                raise ValueError("Wazuh URL port is outside the valid range")
        except ValueError as exc:
            raise ValueError("Wazuh URL must be a valid absolute HTTP(S) origin") from exc
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or not hostname
            or parsed.path not in {"", "/"}
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "Wazuh URL must be an absolute HTTP(S) origin without credentials or path"
            )
        if not username or ":" in username or any(char in username for char in "\r\n"):
            raise ValueError("Wazuh API username is invalid")
        if not password or any(char in password for char in "\r\n"):
            raise ValueError("Wazuh API password is invalid")
        if not 0 < timeout <= 30:
            raise ValueError("Wazuh API timeout must be between 0 and 30 seconds")
        self._base_url = base_url.rstrip("/")
        self._username = username
        self._password = password
        self._timeout = timeout

    def _request(
        self,
        path: str,
        method: str,
        headers: dict[str, str],
    ) -> bytes:
        allowed = {
            ("/security/user/authenticate?raw=true", "POST"),
            ("/", "GET"),
            ("/manager/info", "GET"),
            ("/manager/status", "GET"),
            ("/agents?limit=500&select=id,name,status,ip,version", "GET"),
        }
        if (path, method) not in allowed:
            raise ValueError("Unsupported Wazuh API operation")
        request = Request(
            self._base_url + path,
            headers={**headers, "Accept": "application/json", "User-Agent": "OpenShield/1.0"},
            method=method,
        )
        try:
            opener = build_opener(_NoRedirectHandler())
            with opener.open(request, timeout=self._timeout) as response:
                raw = response.read(self.MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            if exc.code in {401, 403}:
                raise WazuhError(
                    "Wazuh rejected the configured credentials or permissions"
                ) from exc
            if exc.code == 429:
                raise WazuhError("Wazuh API rate limit reached") from exc
            raise WazuhError(f"Wazuh Server API returned HTTP {exc.code}") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise WazuhError("Unable to reach the Wazuh Server API") from exc
        if len(raw) > self.MAX_RESPONSE_BYTES:
            raise WazuhError("Wazuh Server API response exceeded the size limit")
        return raw

    def _login(self) -> str:
        basic = base64.b64encode(
            f"{self._username}:{self._password}".encode("utf-8")
        ).decode("ascii")
        raw = self._request(
            "/security/user/authenticate?raw=true",
            "POST",
            {"Authorization": f"Basic {basic}"},
        )
        try:
            token = raw.decode("utf-8").strip().strip('"')
        except UnicodeDecodeError as exc:
            raise WazuhError("Wazuh authentication returned an invalid token") from exc
        if not token or any(char in token for char in "\r\n"):
            raise WazuhError("Wazuh authentication returned no usable token")
        return token

    def _get(self, path: str, token: str) -> dict[str, object]:
        raw = self._request(path, "GET", {"Authorization": f"Bearer {token}"})
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WazuhError("Wazuh Server API returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise WazuhError("Wazuh Server API returned an unexpected response")
        error = payload.get("error", 0)
        if error not in {0, "0", None}:
            raise WazuhError("Wazuh Server API reported an application error")
        return payload

    def diagnostics(self) -> dict[str, object]:
        token = self._login()
        api = self._get("/", token)
        manager_info = self._get("/manager/info", token)
        manager_status = self._get("/manager/status", token)
        agents = self._get(
            "/agents?limit=500&select=id,name,status,ip,version",
            token,
        )
        data = agents.get("data")
        if not isinstance(data, dict):
            raise WazuhError("Wazuh agents endpoint returned an unexpected response")
        affected_items = data.get("affected_items")
        if not isinstance(affected_items, list):
            raise WazuhError("Wazuh agents endpoint returned an unexpected response")
        total = data.get("total_affected_items", len(affected_items))
        if not isinstance(total, int) or total < len(affected_items):
            raise WazuhError("Wazuh agents endpoint returned an invalid agent count")
        return {
            "api": api,
            "manager_info": manager_info,
            "manager_status": manager_status,
            "agents": agents,
            "summary": {
                "agents_available": total,
                "agents_returned": len(affected_items),
                "agents_limit": self.AGENTS_LIMIT,
            },
        }


class WazuhAdapter:
    kind = "wazuh"
    capabilities: ClassVar[list[Capability]] = [
        Capability.HEALTH_CHECK,
        Capability.READ_CONFIGURATION,
        Capability.READ_EVENTS,
    ]

    def probe(self, integration: Integration) -> dict[str, object]:
        return {
            "integration_id": integration.integration_id,
            "kind": self.kind,
            "status": (
                "configured" if integration.config.get("auth_configured") else "needs_credentials"
            ),
            "transport": "wazuh_server_api",
            "capabilities": [item.value for item in self.capabilities],
        }
