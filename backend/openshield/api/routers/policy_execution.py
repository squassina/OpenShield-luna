from collections.abc import Callable
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query

from openshield.api.schemas import (
    EmergencyStopRequest,
    PolicyCreateRequest,
    PolicyDecisionRejectionRequest,
    PolicyEvaluationRequest,
    PolicyUpdateRequest,
)
from openshield.core.storage import PostgresStore
from openshield.execution.service import (
    ExecutionError,
    approve_decision,
    reject_decision,
)
from openshield.gateway.registry import GatewayConnectionRegistry
from openshield.integrations.registry import IntegrationRegistry
from openshield.policy.engine import (
    create_policy,
    enforcement_enabled,
    evaluate_policy,
    max_autonomy_level,
)

PolicyCreator = Callable[
    [PostgresStore, IntegrationRegistry, dict[str, object]], dict[str, object]
]
PolicyEvaluator = Callable[
    [PostgresStore, IntegrationRegistry, str, str, GatewayConnectionRegistry],
    dict[str, object],
]
DecisionApprover = Callable[
    [PostgresStore, IntegrationRegistry, GatewayConnectionRegistry, str],
    dict[str, object],
]
DecisionRejecter = Callable[[PostgresStore, str, str], dict[str, object]]


def create_policy_execution_router(
    *,
    store: PostgresStore,
    registry: IntegrationRegistry,
    gateway_connections: GatewayConnectionRegistry,
    create_policy_fn: PolicyCreator = create_policy,
    evaluate_policy_fn: PolicyEvaluator = evaluate_policy,
    approve_decision_fn: DecisionApprover = approve_decision,
    reject_decision_fn: DecisionRejecter = reject_decision,
    enforcement_enabled_fn: Callable[[], bool] = enforcement_enabled,
    max_autonomy_level_fn: Callable[[], int] = max_autonomy_level,
) -> APIRouter:
    router = APIRouter()

    @router.get("/api/v1/policies", tags=["policy"])
    def list_policies() -> dict[str, object]:
        return {
            "items": store.list_policies(),
            "max_autonomy_level": max_autonomy_level_fn(),
            "enforcement_enabled": enforcement_enabled_fn(),
            "emergency_stop_active": store.get_emergency_stop(),
        }

    @router.post("/api/v1/policies", status_code=201, tags=["policy"])
    def register_policy(request: PolicyCreateRequest) -> dict[str, object]:
        try:
            return create_policy_fn(store, registry, request.model_dump())
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @router.patch("/api/v1/policies/{policy_id}", tags=["policy"])
    def patch_policy(policy_id: str, request: PolicyUpdateRequest) -> dict[str, object]:
        if store.get_policy(policy_id) is None:
            raise HTTPException(status_code=404, detail="Policy not found")
        result = store.update_policy(
            policy_id, request.model_dump(exclude_unset=True, exclude_none=True)
        )
        if result is None:
            raise HTTPException(status_code=404, detail="Policy not found")
        return result

    @router.get("/api/v1/policy-decisions", tags=["policy"])
    def list_policy_decisions(
        limit: Annotated[int, Query(ge=1, le=200)] = 100,
    ) -> list[dict[str, object]]:
        return store.list_policy_decisions(limit)

    @router.get("/api/v1/executions", tags=["execution"])
    def list_response_executions(
        limit: Annotated[int, Query(ge=1, le=200)] = 100,
    ) -> list[dict[str, object]]:
        return store.list_response_executions(limit)

    @router.get("/api/v1/control/emergency-stop", tags=["execution"])
    def get_emergency_stop() -> dict[str, object]:
        return {
            "active": store.get_emergency_stop(),
            "enforcement_enabled": enforcement_enabled_fn(),
            "max_autonomy_level": max_autonomy_level_fn(),
        }

    @router.post("/api/v1/control/emergency-stop", tags=["execution"])
    def set_emergency_stop(request: EmergencyStopRequest) -> dict[str, object]:
        if not request.active and not enforcement_enabled_fn():
            raise HTTPException(
                status_code=403,
                detail=(
                    "Releasing emergency stop requires enforcement enablement "
                    "and authenticated administration"
                ),
            )
        store.set_emergency_stop(request.active)
        return {"active": store.get_emergency_stop()}

    @router.post("/api/v1/incidents/{incident_id}/evaluate", tags=["policy"])
    def evaluate_incident_policy(
        incident_id: str, request: PolicyEvaluationRequest
    ) -> dict[str, object]:
        try:
            return evaluate_policy_fn(
                store, registry, incident_id, request.policy_id, gateway_connections
            )
        except ExecutionError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @router.post("/api/v1/policy-decisions/{decision_id}/approve", tags=["policy"])
    def approve_policy_decision(decision_id: str) -> dict[str, object]:
        try:
            return approve_decision_fn(store, registry, gateway_connections, decision_id)
        except ExecutionError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @router.post("/api/v1/policy-decisions/{decision_id}/reject", tags=["policy"])
    def reject_policy_decision(
        decision_id: str, request: PolicyDecisionRejectionRequest
    ) -> dict[str, object]:
        try:
            return reject_decision_fn(store, decision_id, request.reason)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    return router
