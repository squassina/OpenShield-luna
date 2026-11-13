import base64
import json
import os
import time
from datetime import UTC, datetime
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit, urlunsplit
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



def _pihole_request(base_url: str, path: str, *, method: str = "GET",
                   body: dict | None = None) -> dict | list:
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
        return _request(
            f"{base_url}{path}", method=method,
            headers={**headers, **({"Content-Type": "application/json"} if body is not None else {})},
            body=json.dumps(body).encode() if body is not None else None,
        )
    finally:
        if sid:
            try:
                _request(f"{base_url}/api/auth", method="DELETE", headers=headers)
            except DnsProviderError:
                pass


def sync_provider_lists(integration: Integration, entries: list[dict[str, object]]) -> dict[str, int | str]:
    desired = {
        (str(item["list_type"]), str(item["domain"])): str(item.get("comment") or "")
        for item in entries
    }
    if integration.kind == "pihole":
        base_url = _base_url(integration)
        response = _pihole_request(base_url, "/api/domains")
        existing = response.get("domains", []) if isinstance(response, dict) else response
        if not isinstance(existing, list):
            raise DnsProviderError("Pi-hole domain-list response has no domains list")
        managed = {}
        all_domains = set()
        for item in existing:
            if not isinstance(item, dict):
                continue
            key = (str(item.get("type")), str(item.get("domain")))
            all_domains.add(key)
            if str(item.get("comment") or "").startswith("OpenShield managed"):
                managed[key] = item
        added = removed = 0
        for list_type, domain in sorted(desired):
            key = ("allow" if list_type == "allow" else "deny", domain)
            if key not in all_domains:
                _pihole_request(
                    base_url, f"/api/domains/{key[0]}/exact", method="POST",
                    body={"domain": domain, "comment": "OpenShield managed"},
                )
                added += 1
        stale = set(managed) - {
            ("allow" if kind == "allow" else "deny", domain)
            for kind, domain in desired
        }
        for list_type, domain in sorted(stale):
            _pihole_request(
                base_url, f"/api/domains/{list_type}/exact/{quote(domain, safe='')}",
                method="DELETE",
            )
            removed += 1
        verified = _pihole_request(base_url, "/api/domains")
        verified_items = verified.get("domains", []) if isinstance(verified, dict) else verified
        verified_keys = {
            (str(item.get("type")), str(item.get("domain")))
            for item in verified_items if isinstance(item, dict)
        }
        expected = {("allow" if kind == "allow" else "deny", domain) for kind, domain in desired}
        if not expected.issubset(verified_keys) or stale.intersection(verified_keys):
            raise DnsProviderError("Pi-hole list synchronization could not be verified")
        return {"provider": "pihole", "added": added, "removed": removed}

    if integration.kind == "adguard":
        base_url = _base_url(integration)
        headers = {"Accept": "application/json"}
        username = os.getenv("OPENSHIELD_ADGUARD_USERNAME", "")
        password = os.getenv("OPENSHIELD_ADGUARD_PASSWORD", "")
        if bool(username) != bool(password):
            raise DnsProviderError("AdGuard username and password must be configured together")
        if username:
            token = base64.b64encode(f"{username}:{password}".encode()).decode()
            headers["Authorization"] = f"Basic {token}"
        current = _request(f"{base_url}/control/filtering/status", headers=headers)
        rules = current.get("user_rules", []) if isinstance(current, dict) else []
        if not isinstance(rules, list) or any(not isinstance(rule, str) for rule in rules):
            raise DnsProviderError("AdGuard filtering status has an invalid user_rules list")
        begin, end = "! OpenShield managed begin", "! OpenShield managed end"
        start = rules.index(begin) if begin in rules else None
        finish = rules.index(end, start + 1) if start is not None and end in rules[start + 1:] else None
        preserved = rules[:start] + rules[finish + 1:] if start is not None and finish is not None else list(rules)
        previous_managed = (
            rules[start:finish + 1]
            if start is not None and finish is not None else []
        )
        managed_rules = [begin]
        for list_type, domain in sorted(desired):
            managed_rules.append(f"{'@@' if list_type == 'allow' else ''}||{domain}^")
        managed_rules.append(end)
        merged = preserved + managed_rules
        previous_set = set(previous_managed)
        managed_set = set(managed_rules)
        added = len((managed_set - previous_set) - {begin, end})
        removed = len((previous_set - managed_set) - {begin, end})
        _request(
            f"{base_url}/control/filtering/set_rules", method="POST",
            headers={**headers, "Content-Type": "application/json"},
            body=json.dumps({"rules": merged}).encode(),
        )
        verified = _request(f"{base_url}/control/filtering/status", headers=headers)
        verified_rules = verified.get("user_rules", []) if isinstance(verified, dict) else []
        if verified_rules != merged:
            raise DnsProviderError("AdGuard list synchronization could not be verified")
        return {
            "provider": "adguard", "added": added, "removed": removed,
        }

    raise DnsProviderError("Unsupported DNS provider for list synchronization")


def _normalize_pihole_records(records: list[object]) -> list[dict]:
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


def _normalize_adguard_records(records: list[object]) -> list[dict]:
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


def _time_value(value: object) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


def fetch_dns_records_page(
    integration: Integration, cursor: dict[str, object] | None = None, page_size: int = 500
) -> tuple[list[dict], dict[str, object], bool]:
    """Fetch one bounded provider page and return its resumable cursor and completion flag."""
    if not 1 <= page_size <= 1000:
        raise ValueError("page_size must be between 1 and 1000")
    base_url = _base_url(integration)

    if integration.kind == "pihole":
        state = dict(cursor or {})
        if state.get("complete") or not state:
            watermark = _time_value(state.get("watermark"))
            window_from = max(0, (watermark - 1) if watermark is not None else time.time() - 86400)
            state = {
                "window_from": window_from, "window_until": time.time(),
                "start": 0, "watermark": watermark,
            }
        params = {
            "from": state["window_from"], "until": state["window_until"],
            "length": page_size, "start": int(state.get("start", 0)),
        }
        result = _pihole_request(base_url, f"/api/queries?{urlencode(params)}")
        records = result.get("queries", result.get("data", [])) if isinstance(result, dict) else result
        if not isinstance(records, list):
            raise DnsProviderError("Pi-hole query-log response has no query list")
        done = len(records) < page_size
        if done:
            next_state = {"watermark": state["window_until"], "complete": True}
        else:
            next_state = {**state, "start": int(state.get("start", 0)) + len(records)}
        return _normalize_pihole_records(records), next_state, done

    if integration.kind == "adguard":
        state = dict(cursor or {})
        if not state or state.get("complete"):
            watermark = _time_value(state.get("watermark"))
            state = {
                "watermark": watermark if watermark is not None else time.time() - 86400,
                "older_than": None, "pages": 0, "newest": None,
            }
        params = {"limit": page_size}
        if state.get("older_than"):
            params["older_than"] = state["older_than"]
        headers = {"Accept": "application/json"}
        username = os.getenv("OPENSHIELD_ADGUARD_USERNAME", "")
        password = os.getenv("OPENSHIELD_ADGUARD_PASSWORD", "")
        if bool(username) != bool(password):
            raise DnsProviderError("AdGuard username and password must be configured together")
        if username:
            token = base64.b64encode(f"{username}:{password}".encode()).decode()
            headers["Authorization"] = f"Basic {token}"
        result = _request(f"{base_url}/control/querylog?{urlencode(params)}", headers=headers)
        records = result.get("data", []) if isinstance(result, dict) else []
        if not isinstance(records, list):
            raise DnsProviderError("AdGuard query-log response has no data list")
        oldest = result.get("oldest") if isinstance(result, dict) else None
        if not oldest and records:
            oldest = records[-1].get("time") if isinstance(records[-1], dict) else None
        newest = state.get("newest")
        if not newest and records and isinstance(records[0], dict):
            newest = records[0].get("time")
        oldest_epoch = _time_value(oldest)
        done = not oldest or oldest_epoch is None or oldest_epoch <= float(state["watermark"])
        if done:
            newest_epoch = _time_value(newest)
            watermark = max(float(state["watermark"]), newest_epoch or 0)
            next_state = {"watermark": watermark, "complete": True}
        else:
            next_state = {
                **state, "older_than": oldest, "pages": int(state.get("pages", 0)) + 1,
                "newest": newest,
            }
        return _normalize_adguard_records(records), next_state, done

    raise DnsProviderError("Unsupported DNS provider")
