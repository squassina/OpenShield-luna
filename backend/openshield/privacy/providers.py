import base64
import json
import os
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

from openshield.integrations.models import Integration

MAX_RESPONSE_BYTES = 5 * 1024 * 1024


class DnsProviderError(RuntimeError):
    pass


def _base_url(integration: Integration) -> str:
    value = integration.config.get("base_url")
    if not isinstance(value, str) or not value:
        raise DnsProviderError("DNS provider integration requires config.base_url")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise DnsProviderError("Provider base_url must be an absolute HTTP(S) URL without credentials")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


def _request(url: str, *, method: str = "GET", headers: dict[str, str] | None = None,
             body: bytes | None = None) -> dict | list:
    request = Request(url, data=body, headers=headers or {}, method=method)
    try:
        with urlopen(request, timeout=5) as response:
            payload = response.read(MAX_RESPONSE_BYTES + 1)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise DnsProviderError(f"DNS provider request failed: {type(exc).__name__}") from exc
    if len(payload) > MAX_RESPONSE_BYTES:
        raise DnsProviderError("DNS provider response exceeds 5 MiB")
    try:
        decoded = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DnsProviderError("DNS provider returned invalid JSON") from exc
    if not isinstance(decoded, (dict, list)):
        raise DnsProviderError("DNS provider returned an unexpected JSON shape")
    return decoded


def _pihole_records(base_url: str) -> list[dict]:
    password = os.getenv("OPENSHIELD_PIHOLE_PASSWORD", "")
    headers = {"Accept": "application/json"}
    sid = None
    if password:
        auth = _request(
            f"{base_url}/api/auth", method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            body=json.dumps({"password": password}).encode(),
        )
        sid = auth.get("session", {}).get("sid") if isinstance(auth, dict) else None
        if not isinstance(sid, str) or not sid:
            raise DnsProviderError("Pi-hole authentication did not return a session")
        headers["X-FTL-SID"] = sid
    try:
        result = _request(f"{base_url}/api/queries?{urlencode({'length': 500})}", headers=headers)
    finally:
        if sid:
            try:
                _request(f"{base_url}/api/auth", method="DELETE", headers=headers)
            except DnsProviderError:
                pass
    records = result.get("queries", result.get("data", [])) if isinstance(result, dict) else result
    if not isinstance(records, list):
        raise DnsProviderError("Pi-hole query-log response has no query list")
    normalized = []
    for item in records:
        if not isinstance(item, dict):
            continue
        normalized.append({
            "domain": item.get("domain") or item.get("name"),
            "client": item.get("client") or item.get("client_ip"),
            "timestamp": item.get("timestamp") or item.get("time"),
            "status": item.get("status") or item.get("reply") or item.get("type"),
            "type": item.get("type") or item.get("query_type"),
        })
    return normalized


def _adguard_records(base_url: str) -> list[dict]:
    headers = {"Accept": "application/json"}
    username = os.getenv("OPENSHIELD_ADGUARD_USERNAME", "")
    password = os.getenv("OPENSHIELD_ADGUARD_PASSWORD", "")
    if bool(username) != bool(password):
        raise DnsProviderError("AdGuard username and password must be configured together")
    if username:
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers["Authorization"] = f"Basic {token}"
    result = _request(f"{base_url}/control/querylog?{urlencode({'limit': 500})}", headers=headers)
    records = result.get("data", []) if isinstance(result, dict) else result
    if not isinstance(records, list):
        raise DnsProviderError("AdGuard query-log response has no data list")
    normalized = []
    for item in records:
        if not isinstance(item, dict):
            continue
        question = item.get("question") if isinstance(item.get("question"), dict) else {}
        normalized.append({
            "domain": question.get("host") or item.get("domain"),
            "client": item.get("client") or item.get("IP"),
            "timestamp": item.get("time") or item.get("timestamp"),
            "status": item.get("reason") or item.get("status"),
            "type": question.get("type") or item.get("type"),
        })
    return normalized


def fetch_dns_records(integration: Integration) -> list[dict]:
    base_url = _base_url(integration)
    if integration.kind == "pihole":
        return _pihole_records(base_url)
    if integration.kind == "adguard":
        return _adguard_records(base_url)
    raise DnsProviderError("Unsupported DNS provider")
