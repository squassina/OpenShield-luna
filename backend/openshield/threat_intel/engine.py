import ipaddress
from datetime import UTC, datetime
from uuid import uuid4

from openshield.core.secrets import SecretConfigurationError, SecretStore
from openshield.core.storage import PostgresStore
from openshield.events.models import EventEnvelope, Severity
from openshield.integrations.models import Integration
from openshield.integrations.registry import IntegrationRegistry
from openshield.privacy.dns import normalize_domain
from openshield.threat_intel.providers import (
    ThreatIntelProviderError,
    lookup_crowdsec,
    lookup_misp,
)

CACHE_TTL_SECONDS = 21600
SEVERITY_POINTS = {
    Severity.INFO: 0,
    Severity.LOW: 10,
    Severity.MEDIUM: 20,
    Severity.HIGH: 30,
    Severity.CRITICAL: 40,
}


def extract_indicators(event: EventEnvelope) -> set[tuple[str, str]]:
    payload = event.payload
    indicators: set[tuple[str, str]] = set()
    ip_fields = ("src_ip", "dest_ip", "id.orig_h", "id.resp_h")
    for field in ip_fields:
        value = payload.get(field)
        if isinstance(value, str):
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            if address.is_global:
                indicators.add(("ip", str(address)))
    domain_values = [
        payload.get("domain"),
        payload.get("query"),
        payload.get("host"),
        payload.get("server_name"),
    ]
    dns = payload.get("dns")
    if isinstance(dns, dict):
        domain_values.append(dns.get("rrname"))
    for value in domain_values:
        if not isinstance(value, str):
            continue
        try:
            indicators.add(("domain", normalize_domain(value)))
        except (TypeError, ValueError):
            continue
    return indicators


def _provider_lookup(
    store: PostgresStore, integration: Integration, secret: dict[str, object],
    indicator_type: str, indicator_value: str,
) -> dict[str, object]:
    cached = store.get_threat_intel_cache(
        integration.integration_id, indicator_type, indicator_value,
    )
    if cached is not None:
        return cached
    api_key = secret.get("api_key")
    if not isinstance(api_key, str) or not api_key:
        raise ThreatIntelProviderError("Provider API key is not configured")
    if integration.kind == "crowdsec":
        if indicator_type != "ip":
            return {
                "provider": "crowdsec", "indicator_type": indicator_type,
                "indicator_value": indicator_value, "matched": False,
                "skipped": "CrowdSec CTI supports IP reputation lookups",
            }
        result = lookup_crowdsec(indicator_value, api_key)
    elif integration.kind == "misp":
        base_url = integration.config.get("base_url")
        if not isinstance(base_url, str) or not base_url:
            raise ThreatIntelProviderError("MISP integration requires config.base_url")
        result = lookup_misp(base_url, api_key, indicator_type, indicator_value)
    else:
        raise ThreatIntelProviderError("Unsupported threat intelligence provider")
    store.set_threat_intel_cache(
        integration.integration_id, indicator_type, indicator_value,
        result, CACHE_TTL_SECONDS,
    )
    return result


def _matched(evidence: dict[str, object]) -> bool:
    if evidence.get("provider") == "crowdsec":
        return bool(evidence.get("matched"))
    if evidence.get("provider") == "misp":
        attributes = evidence.get("attributes")
        return isinstance(attributes, list) and any(
            isinstance(item, dict) and item.get("to_ids") is True for item in attributes
        )
    return False


def _risk_score(
    events: list[EventEnvelope], evidence: dict[str, dict[str, object]]
) -> tuple[int, str, list[dict[str, object]]]:
    factors: list[dict[str, object]] = []
    severity_points = max((SEVERITY_POINTS[event.severity] for event in events), default=0)
    if severity_points:
        factors.append({"factor": "source_event_severity", "points": severity_points})
    crowdsec = next((item for item in evidence.values() if item.get("provider") == "crowdsec"), None)
    if crowdsec and crowdsec.get("matched"):
        reputation = crowdsec.get("reputation")
        points = {"malicious": 35, "suspicious": 25}.get(str(reputation), 10)
        factors.append({"factor": "crowdsec_reputation", "points": points, "value": reputation})
        score = crowdsec.get("score")
        if isinstance(score, (int, float)) and not isinstance(score, bool):
            points = min(15, max(0, round(score * 0.15)))
            if points:
                factors.append({"factor": "crowdsec_score", "points": points})
    misp = next((item for item in evidence.values() if item.get("provider") == "misp"), None)
    if misp:
        attributes = misp.get("attributes")
        actionable = [
            item for item in attributes
            if isinstance(item, dict) and item.get("to_ids") is True
        ] if isinstance(attributes, list) else []
        if actionable:
            points = min(30, 15 + (len(actionable) - 1) * 5)
            factors.append({"factor": "misp_actionable_ioc", "points": points, "count": len(actionable)})
            levels = [
                item.get("threat_level_id") for item in actionable
                if isinstance(item.get("threat_level_id"), int)
            ]
            level = min(levels, default=4)
            threat_points = {1: 20, 2: 12, 3: 5}.get(level, 0)
            if threat_points:
                factors.append({"factor": "misp_event_threat_level", "points": threat_points, "value": level})
    latest = max((event.occurred_at for event in events), default=datetime.now(UTC))
    if latest.tzinfo is None:
        latest = latest.replace(tzinfo=UTC)
    age_seconds = max(0, (datetime.now(UTC) - latest).total_seconds())
    recency = 10 if age_seconds <= 86400 else 5 if age_seconds <= 604800 else 0
    if recency:
        factors.append({"factor": "observation_recency", "points": recency})
    score = min(100, sum(int(item["points"]) for item in factors))
    level = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 35 else "low"
    return score, level, factors


def enrich_events(
    store: PostgresStore, registry: IntegrationRegistry, event_ids: list[str]
) -> dict[str, object]:
    events = store.get_events_by_ids(event_ids)
    if not events:
        raise ValueError("No matching events were found")
    providers = [
        item for item in registry.list_all()
        if item.enabled and item.kind in {"crowdsec", "misp"}
    ]
    if not providers:
        return {"incidents": [], "lookups": 0, "errors": ["No enabled CrowdSec or MISP integrations"]}
    secret_store = SecretStore(store)
    credentials: dict[str, dict[str, object]] = {}
    errors: list[dict[str, str]] = []
    for integration in providers:
        try:
            secret = secret_store.get(integration.integration_id)
            if secret:
                credentials[integration.integration_id] = secret
            else:
                errors.append({"integration_id": integration.integration_id, "error": "api_key_not_configured"})
        except SecretConfigurationError:
            errors.append({"integration_id": integration.integration_id, "error": "secret_store_unavailable"})
    grouped: dict[tuple[str, str], list[EventEnvelope]] = {}
    for event in events:
        for indicator in extract_indicators(event):
            grouped.setdefault(indicator, []).append(event)
    incidents: list[dict[str, object]] = []
    lookups = 0
    for (indicator_type, indicator_value), indicator_events in grouped.items():
        evidence: dict[str, dict[str, object]] = {}
        for integration in providers:
            secret = credentials.get(integration.integration_id)
            if secret is None:
                continue
            if integration.kind == "crowdsec" and indicator_type != "ip":
                continue
            try:
                evidence[integration.integration_id] = _provider_lookup(
                    store, integration, secret, indicator_type, indicator_value,
                )
                lookups += 1
            except (ThreatIntelProviderError, ValueError):
                errors.append({
                    "integration_id": integration.integration_id,
                    "error": "provider_lookup_failed",
                })
        if not any(_matched(item) for item in evidence.values()):
            continue
        risk_score, risk_level, factors = _risk_score(indicator_events, evidence)
        timestamps = [
            event.occurred_at if event.occurred_at.tzinfo else event.occurred_at.replace(tzinfo=UTC)
            for event in indicator_events
        ]
        first_seen = min(timestamps)
        last_seen = max(timestamps)
        source_events = [
            {
                "event_id": event.event_id,
                "event_type": event.event_type,
                "source": event.source.integration_id,
                "severity": event.severity.value,
                "occurred_at": event.occurred_at.isoformat(),
            }
            for event in indicator_events
        ]
        matched_sources = sorted(
            integration_id for integration_id, item in evidence.items() if _matched(item)
        )
        incident = {
            "incident_id": str(uuid4()),
            "indicator_type": indicator_type,
            "indicator_value": indicator_value,
            "title": f"Threat intelligence match: {indicator_value}",
            "summary": (
                f"{indicator_value} matched {', '.join(matched_sources)}; "
                f"risk score {risk_score}/100 ({risk_level})."
            ),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "status": "open",
            "sources": matched_sources,
            "risk_factors": factors,
            "source_events": source_events,
            "intel_evidence": evidence,
            "first_seen_at": first_seen.isoformat(),
            "last_seen_at": last_seen.isoformat(),
            "created_at": datetime.now(UTC).isoformat(),
        }
        incidents.append(store.upsert_incident(
            incident, [event.event_id for event in indicator_events], first_seen, last_seen,
        ))
    return {
        "incidents": incidents,
        "lookups": lookups,
        "events_considered": len(events),
        "indicators_considered": len(grouped),
        "errors": errors,
    }
