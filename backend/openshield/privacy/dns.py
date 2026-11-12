import hashlib
import ipaddress
import re
from datetime import UTC, datetime
from typing import Any

from openshield.events.models import EventEnvelope, EventSource, Severity

TRACKER_SUFFIXES = (
    "doubleclick.net", "googlesyndication.com", "google-analytics.com",
    "googletagmanager.com", "facebook.net", "connect.facebook.net",
    "pixel.facebook.com", "hotjar.com", "mixpanel.com", "segment.io",
    "segment.com", "branch.io", "appsflyer.com", "adjust.com",
)
SUSPICIOUS_SUFFIXES = ("onion", "top", "xyz", "click", "work", "support")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+$")


def normalize_domain(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("DNS query requires a domain")
    domain = value.strip().rstrip(".").lower()
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid DNS domain") from exc
    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError("Invalid DNS domain")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain
    raise ValueError("DNS query domain cannot be an IP address")


def classify_domain(domain: str) -> tuple[str, str]:
    if any(domain == suffix or domain.endswith("." + suffix) for suffix in TRACKER_SUFFIXES):
        return "tracker", "high"
    if domain.rsplit(".", 1)[-1] in SUSPICIOUS_SUFFIXES:
        return "suspicious_tld", "medium"
    return "unclassified", "info"


def normalize_dns_batch(kind: str, integration_id: str, records: list[dict[str, Any]]) -> list[EventEnvelope]:
    if kind not in {"pihole", "adguard"}:
        raise ValueError("Unsupported DNS integration")
    if not 1 <= len(records) <= 500:
        raise ValueError("DNS batch must contain between 1 and 500 records")
    result = []
    for raw in records:
        domain = normalize_domain(raw.get("domain") or raw.get("query"))
        client = raw.get("client") or raw.get("client_ip") or raw.get("client_name")
        if not isinstance(client, str) or len(client) > 255:
            client = None
        timestamp = raw.get("timestamp") or raw.get("time")
        if isinstance(timestamp, (int, float)):
            occurred_at = datetime.fromtimestamp(timestamp, UTC)
        elif isinstance(timestamp, str):
            occurred_at = datetime.fromisoformat(timestamp)
            if occurred_at.tzinfo is None:
                occurred_at = occurred_at.replace(tzinfo=UTC)
            else:
                occurred_at = occurred_at.astimezone(UTC)
        else:
            occurred_at = datetime.now(UTC)
        raw_status = str(raw.get("status") or raw.get("reply") or "unknown").lower()
        blocked = any(word in raw_status for word in ("block", "deny", "filtered", "nxdomain"))
        category, risk = classify_domain(domain)
        event_id = hashlib.sha256(
            f"{kind}|{integration_id}|{occurred_at.isoformat()}|{domain}|{client}|{raw_status}".encode()
        ).hexdigest()
        payload = {
            "domain": domain, "client": client,
            "status": "blocked" if blocked else "allowed",
            "query_type": str(raw.get("type") or raw.get("qtype") or "unknown")[:32],
            "category": category, "risk": risk,
        }
        result.append(EventEnvelope(
            schema_version="openshield.event.v1", event_id=f"dns:{event_id}",
            source=EventSource(integration_id=integration_id, kind=kind),
            event_type="privacy.dns.query", occurred_at=occurred_at,
            observed_at=datetime.now(UTC),
            severity=Severity.HIGH if risk == "high" else Severity.MEDIUM if risk == "medium" else Severity.INFO,
            payload=payload,
        ))
    return result
