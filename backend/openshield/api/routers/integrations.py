from collections.abc import Mapping
from typing import Protocol

from fastapi import APIRouter, HTTPException, Response

from openshield.core.storage import PostgresStore
from openshield.integrations.models import Integration, IntegrationRegistration, IntegrationUpdate
from openshield.integrations.registry import IntegrationRegistry


class IntegrationProbeAdapter(Protocol):
    def probe(self, integration: Integration) -> dict[str, object]: ...


def create_integrations_router(
    *,
    store: PostgresStore,
    registry: IntegrationRegistry,
    adapters: Mapping[str, IntegrationProbeAdapter],
) -> APIRouter:
    router = APIRouter()

    @router.post("/api/v1/integrations", status_code=201, tags=["integrations"])
    def register_integration(registration: IntegrationRegistration) -> dict[str, object]:
        if registration.kind not in adapters:
            raise HTTPException(status_code=400, detail="Unsupported integration kind")
        try:
            item = registry.register(registration)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return item.model_dump(mode="json")

    @router.get("/api/v1/integrations", tags=["integrations"])
    def list_integrations() -> list[dict[str, object]]:
        result = []
        for item in registry.list_all():
            payload = item.model_dump(mode="json")
            if item.kind in {"pihole", "adguard"}:
                payload["config"]["auth_configured"] = (
                    store.get_integration_secret(item.integration_id) is not None
                )
            result.append(payload)
        return result

    @router.patch("/api/v1/integrations/{integration_id}", tags=["integrations"])
    def update_integration(
        integration_id: str, changes: IntegrationUpdate,
    ) -> dict[str, object]:
        if not changes.model_fields_set:
            raise HTTPException(status_code=422, detail="At least one field must be provided")
        item = registry.update(integration_id, changes)
        if item is None:
            raise HTTPException(status_code=404, detail="Integration not found")
        return item.model_dump(mode="json")

    @router.delete(
        "/api/v1/integrations/{integration_id}",
        status_code=204,
        response_class=Response,
        tags=["integrations"],
    )
    def delete_integration(integration_id: str) -> Response:
        if not registry.delete(integration_id):
            raise HTTPException(status_code=404, detail="Integration not found")
        return Response(status_code=204)

    @router.get("/api/v1/integrations/{integration_id}/probe", tags=["integrations"])
    def probe_integration(integration_id: str) -> dict[str, object]:
        item = registry.get(integration_id)
        if item is None:
            raise HTTPException(status_code=404, detail="Integration not found")
        result = adapters[item.kind].probe(item)
        if item.kind in {"crowdsec", "misp", "pihole", "adguard", "openai"}:
            result["credentials_configured"] = (
                store.get_integration_secret(integration_id) is not None
            )
        return result

    return router
