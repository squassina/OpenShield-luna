import ipaddress
import json
import ssl
from datetime import UTC, datetime
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request

from openshield.core.http import safe_urlopen as urlopen
from openshield.integrations.misp import MispClient, MispError

MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class ThreatIntelProviderError(RuntimeError):
    pass


class ThreatIntelIndicatorError(ValueError):
    """An invalid indicator that must not disable its provider."""



def _request(url: str, *, headers: dict[str, str], method: str = "GET",
             body: dict[str, object] | None = None,
             ssl_context: ssl.SSLContext | None = None) -> dict[str, object] | list[object]:
    request = Request(
        url,
        data=json.dumps(body).encode("utf-8") if body is not None else None,
        headers=headers,
        method=method,
    )
    try:
        with urlopen(
            request, timeout=8,
            **({"context": ssl_context} if ssl_context is not None else {}),
        ) as response:
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


def lookup_crowdsec(
    ip_value: str, api_key: str, ssl_context: ssl.SSLContext | None = None,
) -> dict[str, object]:
    try:
        address = ipaddress.ip_address(ip_value)
    except ValueError as exc:
        raise ThreatIntelIndicatorError("CrowdSec lookup requires a valid IP address") from exc
    if not address.is_global:
        raise ThreatIntelIndicatorError("CrowdSec lookup accepts public IP addresses only")
    if not api_key:
        raise ThreatIntelProviderError("CrowdSec API key is not configured")
    result = _request(
        f"https://cti.api.crowdsec.net/v2/smoke/{quote(str(address), safe='')}",
        headers={"Accept": "application/json", "x-api-key": api_key},
        ssl_context=ssl_context,
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
    base_url: str, api_key: str, indicator_type: str, indicator_value: str,
    ssl_context: ssl.SSLContext | None = None,
) -> dict[str, object]:
    if not api_key:
        raise ThreatIntelProviderError("MISP API key is not configured")
    try:
        client = MispClient(
            base_url, api_key, timeout=8, ssl_context=ssl_context,
        )
        attributes = client.search_indicator_attributes(
            indicator_type, indicator_value, limit=50,
        )
    except MispError as exc:
        raise ThreatIntelProviderError("MISP lookup failed") from exc
    return {
        "provider": "misp",
        "indicator_type": indicator_type,
        "indicator_value": indicator_value,
        "matched": bool(attributes),
        "attributes": attributes,
        "source": "MISP REST API",
        "source_url": f"{base_url.rstrip('/')}/attributes/restSearch",
        "fetched_at": datetime.now(UTC).isoformat(),
    }
