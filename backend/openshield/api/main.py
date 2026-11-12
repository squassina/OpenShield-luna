import os
from typing import Annotated

from fastapi import FastAPI, HTTPException, Query, Request, Response
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
adapters = {"openwrt": OpenWrtAdapter()}


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
def list_events() -> list[dict[str, object]]:
    return [event.model_dump(mode="json") for event in store.list_events()]


@app.get("/api/v1/audit", tags=["audit"])
def list_audit_records(
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[dict[str, object]]:
    return store.list_audit(limit)


@app.get("/metrics", response_class=PlainTextResponse, tags=["metrics"], include_in_schema=False)
def prometheus_metrics() -> PlainTextResponse:
    return PlainTextResponse(metrics.render(), media_type="text/plain; version=0.0.4")
