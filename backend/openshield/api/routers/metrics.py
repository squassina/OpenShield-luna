from fastapi import APIRouter
from fastapi.responses import PlainTextResponse

from openshield.core.metrics import MetricsRegistry


def create_metrics_router(metrics: MetricsRegistry) -> APIRouter:
    router = APIRouter()

    @router.get(
        "/metrics", response_class=PlainTextResponse,
        tags=["metrics"], include_in_schema=False,
    )
    def prometheus_metrics() -> PlainTextResponse:
        return PlainTextResponse(metrics.render(), media_type="text/plain; version=0.0.4")

    return router
