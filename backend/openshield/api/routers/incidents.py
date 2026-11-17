from collections.abc import Callable

from fastapi import APIRouter, HTTPException, Query

from openshield.ai.orchestrator import investigate_incident
from openshield.ai.providers import AIProviderError
from openshield.api.schemas import AIInvestigationRequest, IncidentStatusRequest
from openshield.core.secrets import SecretConfigurationError
from openshield.core.storage import PostgresStore
from openshield.integrations.registry import IntegrationRegistry

IncidentInvestigator = Callable[[PostgresStore, IntegrationRegistry, str, str], dict[str, object]]


def create_incidents_router(
    *,
    store: PostgresStore,
    registry: IntegrationRegistry,
    investigate: IncidentInvestigator = investigate_incident,
) -> APIRouter:
    router = APIRouter()

    @router.post("/api/v1/incidents/{incident_id}/investigate", tags=["ai"])
    def investigate_incident_route(
        incident_id: str, request: AIInvestigationRequest
    ) -> dict[str, object]:
        try:
            return investigate(store, registry, incident_id, request.provider_id)
        except AIProviderError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        except SecretConfigurationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @router.get("/api/v1/incidents/{incident_id}/investigations", tags=["ai"])
    def list_incident_investigations(incident_id: str) -> list[dict[str, object]]:
        if store.get_incident(incident_id) is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        return store.list_incident_investigations(incident_id, limit=20)

    @router.get("/api/v1/incidents", tags=["incidents"])
    def list_incidents(
        limit: int = Query(default=100, ge=1, le=200),
        status: str | None = None,
    ) -> list[dict[str, object]]:
        if status is not None and status not in {"open", "acknowledged", "closed", "false_positive"}:
            raise HTTPException(status_code=422, detail="Invalid incident status")
        return store.list_incidents(limit=limit, status=status)

    @router.get("/api/v1/incidents/{incident_id}", tags=["incidents"])
    def get_incident(incident_id: str) -> dict[str, object]:
        incident = store.get_incident(incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        return {
            **incident,
            "timeline": [
                event.model_dump(mode="json")
                for event in store.get_incident_events(incident_id)
            ],
        }

    @router.patch("/api/v1/incidents/{incident_id}", tags=["incidents"])
    def update_incident_status(
        incident_id: str, request: IncidentStatusRequest
    ) -> dict[str, object]:
        incident = store.update_incident_status(incident_id, request.status, request.reason)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        return incident

    return router
