import hashlib
import ipaddress
import json
import re
from datetime import UTC, datetime
from pathlib import Path
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
DATA_DIR = Path(__file__).with_name("data")


def _load_cname_tracker_feed() -> tuple[frozenset[str], dict[str, str]]:
    try:
        metadata = json.loads((DATA_DIR / "cname_trackers_metadata.json").read_text())
        entries = (DATA_DIR / "cname_trackers_justdomains.txt").read_text().splitlines()
    except (OSError, ValueError):
        return frozenset(), {"source": "unavailable", "version": "unavailable", "updated_at": ""}
    domains = frozenset(
        line.strip().lower() for line in entries
        if line.strip() and not line.lstrip().startswith("#")
    )
    return domains, metadata


CNAME_TRACKERS, CNAME_TRACKER_METADATA = _load_cname_tracker_feed()


def normalize_domain(value: Any) -> str:
    if not isinstance(value, str):
        raise TypeError("DNS query requires a domain")
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


def classify_domain_metadata(
    domain: str, override: dict[str, object] | None = None
) -> dict[str, object]:
    if override:
        action = override.get("action")
        if action == "allow":
            category, risk = "allowed_override", "info"
        elif action == "tracker":
            category, risk = "tracker", "high"
        else:
            raise ValueError("Unsupported classification override")
        return {
            "category": category, "risk": risk, "source": "user_override",
            "version": str(override.get("updated_at") or "manual"),
            "updated_at": override.get("updated_at"), "confidence": 1.0,
            "reason": str(override.get("reason") or ""),
        }
    if any(domain == suffix or domain.endswith("." + suffix) for suffix in CNAME_TRACKERS):
        return {
            "category": "tracker", "risk": "high", "source": "adguard_cname_trackers",
            "version": CNAME_TRACKER_METADATA.get("source_commit", "unknown"),
            "updated_at": CNAME_TRACKER_METADATA.get("updated_at"), "confidence": 0.98,
        }
    if any(domain == suffix or domain.endswith("." + suffix) for suffix in TRACKER_SUFFIXES):
        return {
            "category": "tracker", "risk": "high", "source": "openshield_curated_suffixes",
            "version": "1.0.0", "updated_at": "2026-11-13", "confidence": 0.85,
        }
    if domain.rsplit(".", 1)[-1] in SUSPICIOUS_SUFFIXES:
        return {
            "category": "suspicious_tld", "risk": "medium",
            "source": "openshield_suspicious_tld_heuristic",
            "version": "1.0.0", "updated_at": "2026-11-13", "confidence": 0.35,
        }
    return {
        "category": "unclassified", "risk": "info", "source": "none",
        "version": "1.0.0", "updated_at": None, "confidence": 0.0,
    }


def classify_domain(domain: str) -> tuple[str, str]:
    result = classify_domain_metadata(domain)
    return str(result["category"]), str(result["risk"])


def normalize_dns_batch(
    kind: str, integration_id: str, records: list[dict[str, Any]],
    classification_overrides: dict[str, dict[str, object]] | None = None,
) -> list[EventEnvelope]:
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
        override = None
        if classification_overrides:
            matching = [
                (suffix, value) for suffix, value in classification_overrides.items()
                if domain == suffix or domain.endswith("." + suffix)
            ]
            if matching:
                override = max(matching, key=lambda item: len(item[0]))[1]
        classification = classify_domain_metadata(domain, override)
        category, risk = str(classification["category"]), str(classification["risk"])
        event_id = hashlib.sha256(
            f"{kind}|{integration_id}|{occurred_at.isoformat()}|{domain}|{client}|{raw_status}".encode()
        ).hexdigest()
        payload = {
            "domain": domain, "client": client,
            "status": "blocked" if blocked else "allowed",
            "query_type": str(raw.get("type") or raw.get("qtype") or "unknown")[:32],
            "category": category, "risk": risk, "classification": classification,
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
