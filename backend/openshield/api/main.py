from fastapi import FastAPI, HTTPException, status

from openshield.core.auth import Permission, require_permissions
from openshield.core.logging import configure_logging
from openshield.events.models import EventEnvelope
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
adapters = {"openwrt": OpenWrtAdapter()}


@app.get("/health/live", tags=["health"])
def liveness() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health/ready", tags=["health"])
def readiness() -> dict[str, str]:
    return {"status": "ready"}


@app.post(
    "/api/v1/integrations",
    status_code=status.HTTP_201_CREATED,
    tags=["integrations"],
)
def register_integration(
    registration: IntegrationRegistration,
    _principal=__import__("fastapi").Depends(
        require_permissions(Permission.INTEGRATIONS_WRITE)
    ),
) -> dict[str, object]:
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
    dependencies=[__import__("fastapi").Depends(require_permissions(Permission.INTEGRATIONS_READ))],
)
def list_integrations() -> list[dict[str, object]]:
    return [item.model_dump(mode="json") for item in registry.list_all()]


@app.get(
    "/api/v1/integrations/{integration_id}/probe",
    tags=["integrations"],
    dependencies=[__import__("fastapi").Depends(require_permissions(Permission.INTEGRATIONS_READ))],
)
def probe_integration(integration_id: str) -> dict[str, object]:
    item = registry.get(integration_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Integration not found")
    return adapters[item.kind].probe(item)


@app.post(
    "/api/v1/events",
    status_code=status.HTTP_202_ACCEPTED,
    tags=["events"],
)
def ingest_event(
    event: EventEnvelope,
    _principal=__import__("fastapi").Depends(
        require_permissions(Permission.EVENTS_WRITE)
    ),
) -> dict[str, str]:
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
    dependencies=[__import__("fastapi").Depends(require_permissions(Permission.EVENTS_READ))],
)
def list_events() -> list[dict[str, object]]:
    return [event.model_dump(mode="json") for event in events]
