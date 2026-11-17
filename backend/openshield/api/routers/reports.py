from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Query

from openshield.core.storage import PostgresStore
from openshield.gateway.registry import GatewayConnectionRegistry
from openshield.integrations.registry import IntegrationRegistry


def _count_by(items: list[dict[str, object]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = item.get(key)
        label = str(value) if value is not None else "unknown"
        counts[label] = counts.get(label, 0) + 1
    return counts


def create_reports_router(
    *,
    store: PostgresStore,
    registry: IntegrationRegistry,
    gateway_connections: GatewayConnectionRegistry,
) -> APIRouter:
    router = APIRouter()

    @router.get("/api/v1/reports/operations", tags=["reports"])
    def operations_report(
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ) -> dict[str, object]:
        """Bounded operational snapshot across gateways, integrations, incidents and response."""
        gateways = gateway_connections.list_status()
        integrations = registry.list_all()
        incidents = store.list_incidents(limit=limit)
        decisions = store.list_policy_decisions(limit=limit)
        executions = store.list_response_executions(limit=limit)
        audit = store.list_audit(limit)

        return {
            "generated_at": datetime.now(UTC).isoformat(),
            "sample_limit": limit,
            "gateways": {
                "total": len(gateways),
                "by_status": _count_by(gateways, "status"),
                "items": gateways,
            },
            "integrations": {
                "total": len(integrations),
                "enabled": sum(1 for item in integrations if item.enabled),
                "disabled": sum(1 for item in integrations if not item.enabled),
            },
            "incidents": {
                "sampled": len(incidents),
                "by_status": _count_by(incidents, "status"),
                "open": sum(1 for item in incidents if item.get("status") == "open"),
            },
            "policy_decisions": {
                "sampled": len(decisions),
                "by_status": _count_by(decisions, "status"),
                "pending_approval": sum(
                    1 for item in decisions if item.get("status") == "pending_approval"
                ),
            },
            "executions": {
                "sampled": len(executions),
                "by_status": _count_by(executions, "status"),
            },
            "audit": {"recent_records": len(audit), "limit": limit},
        }

    return router
