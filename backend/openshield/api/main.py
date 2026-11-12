import ipaddress
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any

from fastapi import Body, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel, Field

from openshield.core.logging import configure_logging
from openshield.core.metrics import MetricsRegistry
from openshield.core.storage import PostgresStore
from openshield.events.models import EventEnvelope
from openshield.gateway.models import GatewayConnectRequest, GatewayHeartbeatRequest
from openshield.gateway.registry import GatewayConnectionRegistry
from openshield.integrations.models import IntegrationRegistration
from openshield.integrations.openwrt import OpenWrtAdapter
from openshield.integrations.registry import IntegrationRegistry
from openshield.privacy.adapter import DnsPrivacyAdapter
from openshield.privacy.dns import normalize_dns_batch, normalize_domain
from openshield.privacy.providers import DnsProviderError, fetch_dns_records, sync_provider_lists
from openshield.visibility.adapter import NetworkSensorAdapter
from openshield.visibility.normalizers import normalize_sensor_batch

configure_logging()

app = FastAPI(
    title="OpenShield Node API",
    version="0.1.0",
    description="Gateway-first network security and privacy intelligence node.",
)


@app.middleware("http")
async def collect_http_metrics(request: Request, call_next) -> Response:
    try:
        response = await call_next(request)
    except Exception:
        route = request.scope.get("route")
        metrics.increment(
            "openshield_http_requests_total",
            {
                "method": request.method,
                "route": getattr(route, "path", "unmatched"),
                "status": "500",
            },
        )
        raise
    route = request.scope.get("route")
    metrics.increment(
        "openshield_http_requests_total",
        {
            "method": request.method,
            "route": getattr(route, "path", "unmatched"),
            "status": str(response.status_code),
        },
    )
    return response


store = PostgresStore(os.getenv("OPENSHIELD_DATABASE_URL", ""))
registry = IntegrationRegistry(store)
gateway_connections = GatewayConnectionRegistry(store)
metrics = MetricsRegistry()
adapters = {
    "openwrt": OpenWrtAdapter(),
    "suricata": NetworkSensorAdapter("suricata"),
    "zeek": NetworkSensorAdapter("zeek"),
    "pihole": DnsPrivacyAdapter("pihole"),
    "adguard": DnsPrivacyAdapter("adguard"),
}


class PrivacyListEntry(BaseModel):
    list_type: str = Field(pattern=r"^(allow|block)$")
    domain: str = Field(min_length=3, max_length=253)
    comment: str = Field(default="", max_length=500)


DASHBOARD_PATH = Path(__file__).resolve().parents[1] / "dashboard.html"


@app.get("/", response_class=FileResponse, include_in_schema=False)
def dashboard() -> FileResponse:
    if not DASHBOARD_PATH.is_file():
        raise HTTPException(status_code=404, detail="Dashboard asset not found")
    return FileResponse(DASHBOARD_PATH, media_type="text/html")


@app.get("/health/live", tags=["health"])
def liveness() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health/ready", tags=["health"])
def readiness() -> dict[str, str]:
    if not store.is_ready():
        raise HTTPException(status_code=503, detail="Database is not ready")
    return {"status": "ready"}


@app.post("/api/v1/integrations", status_code=201, tags=["integrations"])
def register_integration(registration: IntegrationRegistration) -> dict[str, object]:
    if registration.kind not in adapters:
        raise HTTPException(status_code=400, detail="Unsupported integration kind")
    try:
        item = registry.register(registration)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return item.model_dump(mode="json")


@app.get("/api/v1/integrations", tags=["integrations"])
def list_integrations() -> list[dict[str, object]]:
    return [item.model_dump(mode="json") for item in registry.list_all()]


@app.get("/api/v1/integrations/{integration_id}/probe", tags=["integrations"])
def probe_integration(integration_id: str) -> dict[str, object]:
    item = registry.get(integration_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Integration not found")
    return adapters[item.kind].probe(item)


@app.post("/api/v1/gateway/connect", status_code=201, tags=["gateway"])
def connect_gateway(request: GatewayConnectRequest) -> dict[str, object]:
    # Residential mode: first connection provisions the local gateway integration.
    integration = registry.get(request.gateway_id)
    if integration is None:
        try:
            registry.register(
                IntegrationRegistration(
                    integration_id=request.gateway_id,
                    kind=request.gateway_type,
                    display_name="Home gateway",
                )
            )
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
    elif integration.kind != request.gateway_type:
        raise HTTPException(status_code=409, detail="Gateway integration kind mismatch")

    connection = gateway_connections.connect(request)
    metrics.increment("openshield_gateway_connections_total")
    return {
        "status": "connected",
        "gateway_id": connection.gateway_id,
        "protocol_version": connection.protocol_version,
        "accepted_capabilities": [item.value for item in connection.capabilities],
        "connected_at": connection.connected_at.isoformat(),
    }


@app.post("/api/v1/gateway/heartbeat", tags=["gateway"])
def gateway_heartbeat(request: GatewayHeartbeatRequest) -> dict[str, object]:
    connection = gateway_connections.heartbeat(request.gateway_id)
    if connection is None:
        raise HTTPException(status_code=409, detail="Gateway must connect before sending heartbeat")
    metrics.increment("openshield_gateway_heartbeats_total")
    return {
        "status": "acknowledged",
        "gateway_id": connection.gateway_id,
        "last_seen_at": connection.last_seen_at.isoformat(),
    }


@app.get("/api/v1/gateways", tags=["gateway"])
def list_gateways() -> list[dict[str, object]]:
    return gateway_connections.list_status()


@app.get("/api/v1/gateways/{gateway_id}", tags=["gateway"])
def get_gateway_status(gateway_id: str) -> dict[str, object]:
    gateway = gateway_connections.get_status(gateway_id)
    if gateway is None:
        raise HTTPException(status_code=404, detail="Gateway not found")
    return gateway


@app.post("/api/v1/events", status_code=202, tags=["events"])
def ingest_event(event: EventEnvelope) -> dict[str, str]:
    integration = registry.get(event.source.integration_id)
    if integration is None:
        raise HTTPException(status_code=400, detail="Unknown source integration")
    if integration.kind != event.source.kind:
        raise HTTPException(status_code=400, detail="Event source kind does not match integration")
    inserted = store.insert_event(event)
    if inserted:
        metrics.increment("openshield_events_ingested_total")
    return {"status": "accepted" if inserted else "duplicate", "event_id": event.event_id}


@app.get("/api/v1/events", tags=["events"])
def list_events(
    integration_id: str | None = None,
    event_type: str | None = None,
    severity: str | None = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
) -> list[dict[str, object]]:
    events = store.list_events(
        integration_id=integration_id,
        event_type=event_type,
        severity=severity,
        limit=limit,
    )
    return [event.model_dump(mode="json") for event in events]


@app.post("/api/v1/sensors/{integration_id}/events", status_code=202, tags=["sensors"])
def ingest_sensor_events(
    integration_id: str,
    request: Request,
    records: Annotated[list[dict[str, Any]], Body()],
) -> dict[str, object]:
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Sensor batch body exceeds 5 MiB")
    integration = registry.get(integration_id)
    if integration is None or integration.kind not in {"suricata", "zeek"}:
        raise HTTPException(status_code=404, detail="Network sensor integration not found")
    try:
        events = normalize_sensor_batch(integration.kind, records, integration_id)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    accepted = duplicates = 0
    for event in events:
        if store.insert_event(event):
            accepted += 1
            metrics.increment("openshield_events_ingested_total")
        else:
            duplicates += 1
    return {"accepted": accepted, "duplicates": duplicates, "received": len(events)}


@app.get("/api/v1/sensors", tags=["sensors"])
def list_sensor_health() -> list[dict[str, object]]:
    now = datetime.now(UTC)
    result = []
    stats = store.sensor_event_stats()
    for integration in registry.list_all():
        if integration.kind not in {"suricata", "zeek"}:
            continue
        sensor_stats = stats.get(integration.integration_id, {})
        latest = sensor_stats.get("last_observed_at")
        age = now - latest if latest else None
        result.append({
            "integration_id": integration.integration_id,
            "kind": integration.kind,
            "display_name": integration.display_name,
            "status": "healthy" if age is not None and age <= timedelta(minutes=5)
                else "stale" if age is not None else "no_data",
            "last_event_at": latest.isoformat() if latest else None,
            "events_seen": sensor_stats.get("events_seen", 0),
            "freshness_basis": "node_observed_at",
        })
    return result


def _classify_ip(value: object) -> tuple[str, str] | None:
    if not isinstance(value, str):
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if address.is_unspecified or address.is_multicast:
        return None
    if address.is_loopback:
        scope = "loopback"
    elif address.is_link_local:
        scope = "link_local"
    elif address.is_private:
        scope = "private"
    elif address.is_global:
        scope = "public"
    else:
        scope = "reserved"
    return str(address), scope


@app.get("/api/v1/inventory/devices", tags=["inventory"])
def list_network_devices(
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
) -> list[dict[str, object]]:
    result = []
    for item in store.list_inventory_observations():
        classified = _classify_ip(item["ip_address"])
        if classified is None:
            continue
        address, scope = classified
        result.append({
            "ip_address": address,
            "ip_version": ipaddress.ip_address(address).version,
            "scope": scope,
            "protocols": sorted(item["protocols"]),
            "first_seen": item["first_seen"].isoformat(),
            "last_seen": item["last_seen"].isoformat(),
            "observations": item["observations"],
        })
    result.sort(key=lambda item: item["observations"], reverse=True)
    return result[:limit]


@app.get("/api/v1/inventory/topology", tags=["inventory"])
def get_network_topology(
    limit: Annotated[int, Query(ge=1, le=5000)] = 1000,
) -> dict[str, object]:
    links: dict[tuple[str, str, str], int] = {}
    node_scopes: dict[str, str] = {}
    for item in store.list_topology_observations():
        source_ip = _classify_ip(item["source"])
        target_ip = _classify_ip(item["target"])
        if source_ip is None or target_ip is None:
            continue
        source, source_scope = source_ip
        target, target_scope = target_ip
        node_scopes[source] = source_scope
        node_scopes[target] = target_scope
        links[(source, target, item["protocol"])] = item["observations"]

    edges = []
    for (source, target, protocol), count in list(links.items())[:limit]:
        source_scope = node_scopes[source]
        target_scope = node_scopes[target]
        if source_scope == "private" and target_scope == "public":
            direction = "outbound"
        elif source_scope == "public" and target_scope == "private":
            direction = "inbound"
        elif source_scope == target_scope == "private":
            direction = "internal"
        elif source_scope == target_scope == "public":
            direction = "external"
        else:
            direction = "other"
        edges.append({
            "source": source, "target": target, "protocol": protocol,
            "observations": count, "direction": direction,
        })
    nodes = sorted(node_scopes)
    node_details = [
        {"ip_address": address, "scope": node_scopes[address],
         "ip_version": ipaddress.ip_address(address).version}
        for address in nodes
    ]
    return {"nodes": nodes, "node_details": node_details, "edges": edges}


@app.post("/api/v1/dns/{integration_id}/queries", status_code=202, tags=["privacy"])
def ingest_dns_queries(
    integration_id: str,
    request: Request,
    records: Annotated[list[dict[str, Any]], Body()],
) -> dict[str, object]:
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="DNS batch body exceeds 5 MiB")
    integration = registry.get(integration_id)
    if integration is None or integration.kind not in {"pihole", "adguard"}:
        raise HTTPException(status_code=404, detail="DNS privacy integration not found")
    try:
        events = normalize_dns_batch(integration.kind, integration_id, records)
    except (ValueError, TypeError, OverflowError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    accepted = duplicates = 0
    for event in events:
        if store.insert_event(event):
            accepted += 1
            metrics.increment("openshield_events_ingested_total")
        else:
            duplicates += 1
    return {"accepted": accepted, "duplicates": duplicates, "received": len(events)}


@app.post("/api/v1/privacy/sources/{integration_id}/sync", status_code=202, tags=["privacy"])
def sync_privacy_source(integration_id: str) -> dict[str, object]:
    integration = registry.get(integration_id)
    if integration is None or integration.kind not in {"pihole", "adguard"}:
        raise HTTPException(status_code=404, detail="DNS privacy integration not found")
    try:
        records = fetch_dns_records(integration)
        events = normalize_dns_batch(integration.kind, integration_id, records) if records else []
    except (DnsProviderError, ValueError, TypeError, OverflowError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    accepted = duplicates = 0
    for event in events:
        if store.insert_event(event):
            accepted += 1
            metrics.increment("openshield_events_ingested_total")
        else:
            duplicates += 1
    return {"accepted": accepted, "duplicates": duplicates, "received": len(events)}


@app.get("/api/v1/privacy/sources", tags=["privacy"])
def list_privacy_sources() -> list[dict[str, object]]:
    now = datetime.now(UTC)
    stats = store.privacy_source_stats()
    result = []
    for integration in registry.list_all():
        if integration.kind not in {"pihole", "adguard"}:
            continue
        source = stats.get(integration.integration_id, {})
        latest = source.get("last_observed_at")
        age = now - latest if latest else None
        result.append({
            "integration_id": integration.integration_id,
            "kind": integration.kind,
            "display_name": integration.display_name,
            "status": "healthy" if age is not None and age <= timedelta(minutes=5)
                else "stale" if age is not None else "no_data",
            "last_query_at": latest.isoformat() if latest else None,
            "queries_seen": source.get("queries_seen", 0),
            "freshness_basis": "node_observed_at",
        })
    return result


@app.get("/api/v1/privacy/analytics/domains", tags=["privacy"])
def privacy_domain_analytics(
    days: Annotated[int, Query(ge=1, le=365)] = 30,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[dict[str, object]]:
    return store.privacy_domain_stats(days, limit)


@app.get("/api/v1/privacy/analytics/devices", tags=["privacy"])
def privacy_device_analytics(
    days: Annotated[int, Query(ge=1, le=365)] = 30,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[dict[str, object]]:
    return store.privacy_client_stats(days, limit)


@app.get("/api/v1/privacy/trends", tags=["privacy"])
def privacy_trends(
    days: Annotated[int, Query(ge=1, le=365)] = 30,
) -> list[dict[str, object]]:
    return store.privacy_trends(days)


@app.get("/api/v1/privacy/report", tags=["privacy"])
def privacy_report(
    days: Annotated[int, Query(ge=1, le=365)] = 30,
) -> dict[str, object]:
    trends = store.privacy_trends(days)
    domains = store.privacy_domain_stats(days, 10)
    devices = store.privacy_client_stats(days, 10)
    queries = sum(item["queries"] for item in trends)
    blocked = sum(item["blocked"] for item in trends)
    tracker_queries = sum(item["tracker_queries"] for item in trends)
    totals = {
        "queries": queries, "blocked": blocked, "tracker_queries": tracker_queries,
        "block_rate_percent": round(blocked * 100 / queries, 2) if queries else 0.0,
        "tracker_rate_percent": round(tracker_queries * 100 / queries, 2) if queries else 0.0,
    }
    return {
        "period_days": days, "generated_at": datetime.now(UTC).isoformat(),
        "totals": totals, "top_domains": domains, "top_devices": devices,
        "daily_trends": trends,
        "classification_notice": "Domain classification is heuristic and is not a threat verdict.",
    }


@app.get("/api/v1/privacy/lists", tags=["privacy"])
def list_privacy_lists(integration_id: str | None = None) -> list[dict[str, object]]:
    return store.list_privacy_lists(integration_id)


@app.post("/api/v1/privacy/lists", status_code=201, tags=["privacy"])
def add_privacy_list_entry(entry: PrivacyListEntry) -> dict[str, object]:
    try:
        domain = normalize_domain(entry.domain)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    store.upsert_privacy_list("openshield-local", entry.list_type, domain, entry.comment)
    return {
        "integration_id": "openshield-local", "list_type": entry.list_type,
        "domain": domain, "comment": entry.comment,
    }


@app.post("/api/v1/privacy/lists/{integration_id}/sync", status_code=200, tags=["privacy"])
def sync_privacy_lists(integration_id: str) -> dict[str, object]:
    integration = registry.get(integration_id)
    if integration is None or integration.kind not in {"pihole", "adguard"}:
        raise HTTPException(status_code=404, detail="DNS privacy integration not found")
    entries = store.list_privacy_lists("openshield-local")
    try:
        result = sync_provider_lists(integration, entries)
    except DnsProviderError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    store.write_audit(
        "privacy.provider_lists.synchronized", None, integration_id,
        {"provider": integration.kind, "entry_count": len(entries), "result": result},
    )
    return {"integration_id": integration_id, "entries": len(entries), **result}


@app.delete("/api/v1/privacy/lists/{list_type}/{domain}", status_code=204, tags=["privacy"])
def remove_privacy_list_entry(list_type: str, domain: str) -> Response:
    if list_type not in {"allow", "block"}:
        raise HTTPException(status_code=422, detail="list_type must be allow or block")
    try:
        normalized = normalize_domain(domain)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if not store.delete_privacy_list_item("openshield-local", list_type, normalized):
        raise HTTPException(status_code=404, detail="Privacy list entry not found")
    return Response(status_code=204)


@app.get("/api/v1/audit", tags=["audit"])
def list_audit_records(
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[dict[str, object]]:
    return store.list_audit(limit)


@app.get("/metrics", response_class=PlainTextResponse, tags=["metrics"], include_in_schema=False)
def prometheus_metrics() -> PlainTextResponse:
    return PlainTextResponse(metrics.render(), media_type="text/plain; version=0.0.4")
