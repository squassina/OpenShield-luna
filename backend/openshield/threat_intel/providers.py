import ipaddress
import json
from datetime import UTC, datetime
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class ThreatIntelProviderError(RuntimeError):
    pass


def _request(url: str, *, headers: dict[str, str], method: str = "GET",
             body: dict[str, object] | None = None) -> dict[str, object] | list[object]:
    request = Request(
        url,
        data=json.dumps(body).encode("utf-8") if body is not None else None,
        headers=headers,
        method=method,
    )
    try:
        with urlopen(request, timeout=8) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        raise ThreatIntelProviderError(f"Threat intelligence provider returned HTTP {exc.code}") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise ThreatIntelProviderError("Unable to reach threat intelligence provider") from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ThreatIntelProviderError("Threat intelligence response exceeds 2 MiB")
    try:
        result = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ThreatIntelProviderError("Threat intelligence provider returned invalid JSON") from exc
    if not isinstance(result, (dict, list)):
        raise ThreatIntelProviderError("Threat intelligence provider returned an unexpected JSON shape")
    return result


def lookup_crowdsec(ip_value: str, api_key: str) -> dict[str, object]:
    try:
        address = ipaddress.ip_address(ip_value)
    except ValueError as exc:
        raise ValueError("CrowdSec lookup requires a valid IP address") from exc
    if not address.is_global:
        raise ValueError("CrowdSec lookup accepts public IP addresses only")
    if not api_key:
        raise ThreatIntelProviderError("CrowdSec API key is not configured")
    result = _request(
        f"https://cti.api.crowdsec.net/v2/smoke/{quote(str(address), safe='')}",
        headers={"Accept": "application/json", "x-api-key": api_key},
    )
    if not isinstance(result, dict):
        raise ThreatIntelProviderError("CrowdSec returned an invalid reputation report")
    reputation = result.get("reputation")
    if not isinstance(reputation, str):
        reputation = "unknown"
    scores = result.get("scores") if isinstance(result.get("scores"), dict) else {}
    score = scores.get("overall", result.get("score"))
    if not isinstance(score, (int, float)) or isinstance(score, bool):
        score = None
    behaviors = result.get("behaviors") if isinstance(result.get("behaviors"), list) else []
    classifications = result.get("classifications") if isinstance(result.get("classifications"), list) else []
    normalized_behaviors = [
        item.get("label") or item.get("name") or item.get("value")
        if isinstance(item, dict) else str(item)
        for item in behaviors[:20]
    ]
    normalized_classifications = [
        item.get("label") or item.get("name") or item.get("value")
        if isinstance(item, dict) else str(item)
        for item in classifications[:20]
    ]
    matched = reputation.lower() in {"malicious", "suspicious"} or bool(
        isinstance(score, (int, float)) and score >= 20
    )
    return {
        "provider": "crowdsec",
        "indicator_type": "ip",
        "indicator_value": str(address),
        "matched": matched,
        "reputation": reputation.lower(),
        "score": score,
        "behaviors": normalized_behaviors,
        "classifications": normalized_classifications,
        "source": "CrowdSec CTI Enrichment API",
        "source_url": "https://cti.api.crowdsec.net/v2/smoke/",
        "fetched_at": datetime.now(UTC).isoformat(),
    }


def lookup_misp(
    base_url: str, api_key: str, indicator_type: str, indicator_value: str
) -> dict[str, object]:
    parsed = urlsplit(base_url)
    if (
        parsed.scheme not in {"http", "https"} or not parsed.netloc
        or parsed.username or parsed.password or parsed.query or parsed.fragment
    ):
        raise ValueError("MISP base URL must be an absolute HTTP(S) URL without credentials")
    if not api_key:
        raise ThreatIntelProviderError("MISP API key is not configured")
    result = _request(
        f"{base_url.rstrip('/')}/attributes/restSearch",
        method="POST",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": api_key,
        },
        body={"returnFormat": "json", "value": indicator_value, "limit": 50, "page": 1},
    )
    response = result.get("response", result) if isinstance(result, dict) else result
    if isinstance(response, dict):
        attributes = response.get("Attribute", response.get("attributes", []))
        if not attributes and isinstance(response.get("response"), list):
            attributes = response["response"]
    else:
        attributes = response
    if not isinstance(attributes, list):
        attributes = []
    normalized = []
    for item in attributes[:50]:
        if not isinstance(item, dict):
            continue
        attribute = item.get("Attribute") if isinstance(item.get("Attribute"), dict) else item
        event = item.get("Event") if isinstance(item.get("Event"), dict) else {}
        tags = attribute.get("Tag") or event.get("Tag") or []
        tag_names = [
            tag.get("name") for tag in tags
            if isinstance(tag, dict) and isinstance(tag.get("name"), str)
        ] if isinstance(tags, list) else []
        to_ids = attribute.get("to_ids") in {True, "1", "true"}
        try:
            threat_level_id = int(event.get("threat_level_id", 4))
        except (TypeError, ValueError):
            threat_level_id = 4
        normalized.append({
            "attribute_id": str(attribute.get("id", "")),
            "type": str(attribute.get("type", "")),
            "value": str(attribute.get("value", indicator_value)),
            "to_ids": to_ids,
            "category": str(attribute.get("category", "")),
            "event_id": str(event.get("id", attribute.get("event_id", ""))),
            "event_info": str(event.get("info", ""))[:256],
            "threat_level_id": threat_level_id,
            "tags": tag_names[:20],
            "timestamp": str(attribute.get("timestamp", event.get("timestamp", ""))),
        })
    return {
        "provider": "misp",
        "indicator_type": indicator_type,
        "indicator_value": indicator_value,
        "matched": bool(normalized),
        "attributes": normalized,
        "source": "MISP REST API",
        "source_url": f"{base_url.rstrip('/')}/attributes/restSearch",
        "fetched_at": datetime.now(UTC).isoformat(),
    }
