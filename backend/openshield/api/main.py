import ipaddress
import os
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import Body, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import PlainTextResponse

from openshield.core.logging import configure_logging
from openshield.core.metrics import MetricsRegistry
from openshield.core.storage import PostgresStore
from openshield.events.models import EventEnvelope
from openshield.gateway.models import GatewayConnectRequest, GatewayHeartbeatRequest
from openshield.gateway.registry import GatewayConnectionRegistry
from openshield.integrations.models import IntegrationRegistration
from openshield.integrations.openwrt import OpenWrtAdapter
from openshield.integrations.registry import IntegrationRegistry
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
adapters = {"openwrt": OpenWrtAdapter(), "suricata": NetworkSensorAdapter("suricata"), "zeek": NetworkSensorAdapter("zeek")}


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
    devices: dict[str, dict[str, Any]] = {}
    for event in store.list_events():
        payload = event.payload
        addresses = [
            payload.get(key) for key in ("src_ip", "dest_ip", "id.orig_h", "id.resp_h")
        ]
        for raw_address in addresses:
            classified = _classify_ip(raw_address)
            if classified is None:
                continue
            address, scope = classified
            item = devices.setdefault(address, {
                "ip_address": address, "ip_version": ipaddress.ip_address(address).version,
                "scope": scope, "protocols": set(),
                "first_seen": event.occurred_at, "last_seen": event.occurred_at,
                "observations": 0,
            })
            item["protocols"].add(str(payload.get("proto") or payload.get("app_proto") or "unknown"))
            item["first_seen"] = min(item["first_seen"], event.occurred_at)
            item["last_seen"] = max(item["last_seen"], event.occurred_at)
            item["observations"] += 1
    result = [{
        **item,
        "protocols": sorted(item["protocols"]),
        "first_seen": item["first_seen"].isoformat(),
        "last_seen": item["last_seen"].isoformat(),
    } for item in devices.values()]
    result.sort(key=lambda item: item["observations"], reverse=True)
    return result[:limit]


@app.get("/api/v1/inventory/topology", tags=["inventory"])
def get_network_topology(
    limit: Annotated[int, Query(ge=1, le=5000)] = 1000,
) -> dict[str, object]:
    nodes: set[str] = set()
    node_scopes: dict[str, str] = {}
    links: dict[tuple[str, str, str], int] = {}
    for event in store.list_events():
        payload = event.payload
        source = payload.get("src_ip") or payload.get("id.orig_h")
        target = payload.get("dest_ip") or payload.get("id.resp_h")
        source_ip = _classify_ip(source)
        target_ip = _classify_ip(target)
        if source_ip is None or target_ip is None:
            continue
        source, source_scope = source_ip
        target, target_scope = target_ip
        protocol = str(payload.get("proto") or payload.get("app_proto") or "unknown")
        nodes.update((source, target))
        node_scopes[source] = source_scope
        node_scopes[target] = target_scope
        key = (source, target, protocol)
        links[key] = links.get(key, 0) + 1
    edges = []
    for (source, target, protocol), count in sorted(
        links.items(), key=lambda item: item[1], reverse=True
    )[:limit]:
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
    node_details = [
        {"ip_address": address, "scope": node_scopes[address],
         "ip_version": ipaddress.ip_address(address).version}
        for address in sorted(nodes)
    ]
    return {"nodes": sorted(nodes), "node_details": node_details, "edges": edges}


@app.get("/api/v1/audit", tags=["audit"])
def list_audit_records(
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[dict[str, object]]:
    return store.list_audit(limit)


@app.get("/metrics", response_class=PlainTextResponse, tags=["metrics"], include_in_schema=False)
def prometheus_metrics() -> PlainTextResponse:
    return PlainTextResponse(metrics.render(), media_type="text/plain; version=0.0.4")
