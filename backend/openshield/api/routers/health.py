from fastapi import APIRouter, HTTPException

from openshield.core.storage import PostgresStore


def create_health_router(store: PostgresStore) -> APIRouter:
    router = APIRouter()

    @router.get("/health/live", tags=["health"])
    def liveness() -> dict[str, str]:
        return {"status": "alive"}

    @router.get("/health/ready", tags=["health"])
    def readiness() -> dict[str, str]:
        if not store.is_ready():
            raise HTTPException(status_code=503, detail="Database is not ready")
        return {"status": "ready"}

    return router
