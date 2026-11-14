from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class MispError(RuntimeError):
    """Credential-free MISP API error."""


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class MispClient:
    """Read-only MISP API client for published IDS attributes."""

    MAX_RESPONSE_BYTES = 5 * 1024 * 1024
    MAX_INDICATORS = 1000
    INDICATOR_TYPES = ("ip-src", "ip-dst", "domain", "hostname", "url")

    def __init__(self, base_url: str, api_key: str, timeout: float = 10.0) -> None:
        try:
            parsed = urlsplit(base_url)
            hostname = parsed.hostname
            if parsed.port is not None and not 1 <= parsed.port <= 65535:
                raise ValueError("MISP URL port is outside the valid range")
        except ValueError as exc:
            raise ValueError("MISP URL must be a valid absolute HTTP(S) origin") from exc
        if (
            parsed.scheme not in {"http", "https"} or not parsed.netloc or not hostname
            or parsed.path not in {"", "/"} or parsed.username or parsed.password
            or parsed.query or parsed.fragment
        ):
            raise ValueError("MISP URL must be an absolute HTTP(S) origin without credentials or path")
        if not api_key or "\r" in api_key or "\n" in api_key:
            raise ValueError("MISP API key is required")
        if not 0 < timeout <= 30:
            raise ValueError("MISP API timeout must be between 0 and 30 seconds")
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout

    def _request(self, path: str, method: str, body: bytes | None = None) -> object:
        if (path, method) not in {
            ("/servers/getVersion", "GET"),
            ("/attributes/restSearch", "POST"),
        }:
            raise ValueError("Unsupported MISP API operation")
        headers = {
            "Authorization": self._api_key,
            "Accept": "application/json",
            "User-Agent": "OpenShield/1.0",
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = Request(self._base_url + path, data=body, headers=headers, method=method)
        try:
            with build_opener(_NoRedirectHandler()).open(request, timeout=self._timeout) as response:
                raw = response.read(self.MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            if exc.code in {401, 403}:
                raise MispError("MISP rejected the configured API key or permissions") from exc
            raise MispError(f"MISP API returned HTTP {exc.code}") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise MispError("Unable to reach the MISP API") from exc
        if len(raw) > self.MAX_RESPONSE_BYTES:
            raise MispError("MISP API response exceeded the size limit")
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MispError("MISP API returned invalid JSON") from exc
        if not isinstance(payload, (dict, list)):
            raise MispError("MISP API returned an unexpected response")
        return payload

    def diagnostics(self) -> dict[str, object]:
        payload = self._request("/servers/getVersion", "GET")
        if not isinstance(payload, dict) or not isinstance(payload.get("version"), str):
            raise MispError("MISP version endpoint returned an unexpected response")
        return {"version": payload["version"], "api": "connected"}

    def search_indicators(self, limit: int = 1000) -> list[dict[str, object]]:
        if not 1 <= limit <= self.MAX_INDICATORS:
            raise ValueError("MISP indicator limit must be between 1 and 1000")
        body = json.dumps({
            "returnFormat": "json",
            "type": list(self.INDICATOR_TYPES),
            "to_ids": True,
            "limit": limit,
            "page": 1,
        }).encode("utf-8")
        payload = self._request("/attributes/restSearch", "POST", body)
        response = payload.get("response") if isinstance(payload, dict) else None
        attributes = response.get("Attribute") if isinstance(response, dict) else None
        if not isinstance(attributes, list):
            raise MispError("MISP attribute search returned an unexpected response")

        result = []
        for item in attributes:
            if not isinstance(item, dict):
                continue
            to_ids = item.get("to_ids")
            if not (to_ids is True or to_ids == 1 or to_ids == "1" or to_ids == "true"):
                continue
            indicator_type = item.get("type")
            value = item.get("value")
            identifier = item.get("uuid") or item.get("id")
            if (
                indicator_type not in self.INDICATOR_TYPES
                or not isinstance(value, str) or not value.strip() or len(value) > 2048
                or not isinstance(identifier, (str, int))
            ):
                continue
            result.append({
                "indicator_id": str(identifier),
                "indicator_type": indicator_type,
                "value": value.strip(),
                "category": str(item.get("category") or "")[:120],
                "event_id": str(item.get("event_id") or "")[:128],
                "comment": str(item.get("comment") or "")[:500],
                "to_ids": True,
                "source_timestamp": str(item.get("timestamp") or "")[:40],
            })
        return result


class MispAdapter:
    kind = "misp"

    def probe(self, integration) -> dict[str, object]:
        return {
            "integration_id": integration.integration_id,
            "kind": self.kind,
            "status": "configured" if integration.config.get("auth_configured") else "needs_credentials",
            "transport": "misp_rest_api",
            "capabilities": ["health_check", "read_events"],
        }
