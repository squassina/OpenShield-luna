from typing import Annotated

from fastapi import APIRouter, Query

from openshield.core.storage import PostgresStore


def create_audit_router(*, store: PostgresStore) -> APIRouter:
    router = APIRouter()

    @router.get("/api/v1/audit", tags=["audit"])
    def list_audit_records(
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ) -> list[dict[str, object]]:
        return store.list_audit(limit)

    return router
