from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status

from openshield.core.auth import (
    Permission,
    Principal,
    Role,
    authentication_is_configured,
    require_permissions,
)
from openshield.core.logging import configure_logging
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

registry = IntegrationRegistry()
events: list[EventEnvelope] = []
gateway_connections = GatewayConnectionRegistry()
adapters = {"openwrt": OpenWrtAdapter()}


@app.get("/health/live", tags=["health"])
def liveness() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health/ready", tags=["health"])
def readiness() -> dict[str, str]:
    if not authentication_is_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication configuration is not ready",
        )
    return {"status": "ready"}


@app.post(
    "/api/v1/integrations",
    status_code=status.HTTP_201_CREATED,
    tags=["integrations"],
    dependencies=[Depends(require_permissions(Permission.INTEGRATIONS_WRITE))],
)
def register_integration(registration: IntegrationRegistration) -> dict[str, object]:
    adapter = adapters.get(registration.kind)
    if adapter is None:
        raise HTTPException(status_code=400, detail="Unsupported integration kind")
    try:
        item = registry.register(registration)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return item.model_dump(mode="json")


@app.get(
    "/api/v1/integrations",
    tags=["integrations"],
    dependencies=[Depends(require_permissions(Permission.INTEGRATIONS_READ))],
)
def list_integrations() -> list[dict[str, object]]:
    return [item.model_dump(mode="json") for item in registry.list_all()]


@app.get(
    "/api/v1/integrations/{integration_id}/probe",
    tags=["integrations"],
    dependencies=[Depends(require_permissions(Permission.INTEGRATIONS_READ))],
)
def probe_integration(integration_id: str) -> dict[str, object]:
    item = registry.get(integration_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Integration not found")
    return adapters[item.kind].probe(item)


@app.post(
    "/api/v1/gateway/connect",
    status_code=status.HTTP_201_CREATED,
    tags=["gateway"],
)
def connect_gateway(
    request: GatewayConnectRequest,
    principal: Annotated[
        Principal, Depends(require_permissions(Permission.GATEWAY_CONNECT))
    ],
) -> dict[str, object]:
    if principal.key_id != request.gateway_id:
        raise HTTPException(status_code=403, detail="Gateway identity does not match API key")
    connection = gateway_connections.connect(request)
    return {
        "status": "connected",
        "gateway_id": connection.gateway_id,
        "protocol_version": connection.protocol_version,
        "accepted_capabilities": [item.value for item in connection.capabilities],
        "connected_at": connection.connected_at.isoformat(),
    }


@app.post(
    "/api/v1/gateway/heartbeat",
    tags=["gateway"],
)
def gateway_heartbeat(
    request: GatewayHeartbeatRequest,
    principal: Annotated[
        Principal, Depends(require_permissions(Permission.GATEWAY_HEARTBEAT))
    ],
) -> dict[str, object]:
    connection = gateway_connections.heartbeat(principal.key_id)
    if connection is None:
        raise HTTPException(status_code=409, detail="Gateway must connect before sending heartbeat")
    return {
        "status": "acknowledged",
        "gateway_id": connection.gateway_id,
        "last_seen_at": connection.last_seen_at.isoformat(),
    }


@app.get(
    "/api/v1/gateways",
    tags=["gateway"],
    dependencies=[Depends(require_permissions(Permission.GATEWAY_READ))],
)
def list_gateways() -> list[dict[str, object]]:
    return gateway_connections.list_status()


@app.get(
    "/api/v1/gateways/{gateway_id}",
    tags=["gateway"],
    dependencies=[Depends(require_permissions(Permission.GATEWAY_READ))],
)
def get_gateway_status(gateway_id: str) -> dict[str, object]:
    gateway = gateway_connections.get_status(gateway_id)
    if gateway is None:
        raise HTTPException(status_code=404, detail="Gateway not found")
    return gateway


@app.post(
    "/api/v1/events",
    status_code=status.HTTP_202_ACCEPTED,
    tags=["events"],
    dependencies=[Depends(require_permissions(Permission.EVENTS_WRITE))],
)
def ingest_event(
    event: EventEnvelope,
    principal: Annotated[Principal, Depends(require_permissions(Permission.EVENTS_WRITE))],
) -> dict[str, str]:
    if principal.role == Role.GATEWAY and event.source.integration_id != principal.key_id:
        raise HTTPException(status_code=403, detail="Gateway cannot ingest events for another integration")
    integration = registry.get(event.source.integration_id)
    if integration is None:
        raise HTTPException(status_code=400, detail="Unknown source integration")
    if integration.kind != event.source.kind:
        raise HTTPException(status_code=400, detail="Event source kind does not match integration")
    events.append(event)
    return {"status": "accepted", "event_id": event.event_id}


@app.get(
    "/api/v1/events",
    tags=["events"],
    dependencies=[Depends(require_permissions(Permission.EVENTS_READ))],
)
def list_events() -> list[dict[str, object]]:
    return [event.model_dump(mode="json") for event in events]
