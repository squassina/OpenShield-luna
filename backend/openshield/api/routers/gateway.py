from collections.abc import Callable

from fastapi import APIRouter, HTTPException, Request

from openshield.core.metrics import MetricsRegistry
from openshield.core.secrets import SecretConfigurationError
from openshield.core.storage import PostgresStore
from openshield.execution.service import process_gateway_command_result
from openshield.gateway.models import (
    GatewayCommandResultRequest,
    GatewayConnectRequest,
    GatewayHeartbeatRequest,
)
from openshield.gateway.registry import GatewayConnectionRegistry
from openshield.integrations.models import IntegrationRegistration
from openshield.integrations.registry import IntegrationRegistry


def create_gateway_router(
    *,
    store: PostgresStore,
    registry: IntegrationRegistry,
    gateway_connections: GatewayConnectionRegistry,
    metrics: MetricsRegistry,
    gateway_openwrt_config: Callable[[str], dict[str, object] | None],
    gateway_token_valid: Callable[[Request], bool],
) -> APIRouter:
    router = APIRouter()

    @router.get("/api/v1/gateway/config/{gateway_id}", tags=["gateway"])
    def gateway_configuration(gateway_id: str, request: Request) -> dict[str, object]:
        if not gateway_token_valid(request):
            raise HTTPException(status_code=401, detail="Gateway authentication required")
        integration = registry.get(gateway_id)
        if integration is None or integration.kind != "openwrt":
            raise HTTPException(status_code=404, detail="Gateway integration not found")
        try:
            credentials = gateway_openwrt_config(gateway_id)
        except SecretConfigurationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        return {"gateway_id": gateway_id, "openwrt_config": credentials}

    @router.post("/api/v1/gateway/connect", status_code=201, tags=["gateway"])
    def connect_gateway(
        request: GatewayConnectRequest, http_request: Request,
    ) -> dict[str, object]:
        # Residential mode: first connection provisions the local gateway integration.
        integration = registry.get(request.gateway_id)
        if integration is None:
            try:
                integration = registry.register(
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

        encrypted_secret = store.get_integration_secret(request.gateway_id)
        if encrypted_secret and not gateway_token_valid(http_request):
            raise HTTPException(
                status_code=401,
                detail="Gateway authentication required to receive router credentials",
            )
        connection = gateway_connections.connect(request)
        metrics.increment("openshield_gateway_connections_total")
        try:
            openwrt_config = (
                gateway_openwrt_config(connection.gateway_id) if encrypted_secret else None
            )
        except SecretConfigurationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        return {
            "status": "connected",
            "gateway_id": connection.gateway_id,
            "integration_id": integration.integration_id,
            "protocol_version": connection.protocol_version,
            "accepted_capabilities": [item.value for item in connection.capabilities],
            "connected_at": connection.connected_at.isoformat(),
            "openwrt_config": openwrt_config,
            "commands": store.list_pending_gateway_commands(connection.gateway_id, limit=10),
        }

    @router.post("/api/v1/gateway/heartbeat", tags=["gateway"])
    def gateway_heartbeat(
        request: GatewayHeartbeatRequest, http_request: Request,
    ) -> dict[str, object]:
        connection = gateway_connections.heartbeat(request.gateway_id)
        if connection is None:
            raise HTTPException(
                status_code=409, detail="Gateway must connect before sending heartbeat",
            )
        encrypted_secret = store.get_integration_secret(connection.gateway_id)
        if encrypted_secret and not gateway_token_valid(http_request):
            raise HTTPException(
                status_code=401,
                detail="Gateway authentication required to receive router credentials",
            )
        metrics.increment("openshield_gateway_heartbeats_total")
        if request.spool_stats is not None:
            # Connector-reported telemetry is for monitoring only, never policy decisions.
            labels = {"gateway_id": connection.gateway_id}
            stats = request.spool_stats
            metrics.set_gauge("openshield_gateway_spool_pending_events", stats.pending_events, labels)
            metrics.set_gauge("openshield_gateway_spool_capacity", stats.capacity, labels)
            metrics.set_counter("openshield_gateway_spool_evicted_events_total", stats.evicted_events, labels)
            metrics.set_counter(
                "openshield_gateway_spool_coalesced_health_events_total",
                stats.coalesced_health_events,
                labels,
            )
            metrics.set_counter("openshield_gateway_spool_dropped_events_total", stats.dropped_events, labels)
            metrics.set_gauge(
                "openshield_gateway_spool_last_report_timestamp_seconds",
                connection.last_seen_at.timestamp(),
                labels,
            )
        try:
            openwrt_config = (
                gateway_openwrt_config(connection.gateway_id) if encrypted_secret else None
            )
        except SecretConfigurationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        return {
            "status": "acknowledged",
            "gateway_id": connection.gateway_id,
            "last_seen_at": connection.last_seen_at.isoformat(),
            "openwrt_config": openwrt_config,
            "commands": store.list_pending_gateway_commands(connection.gateway_id, limit=10),
        }

    @router.post(
        "/api/v1/gateway/commands/{gateway_id}/{command_id}/result", tags=["gateway"],
    )
    def report_gateway_command_result(
        gateway_id: str,
        command_id: str,
        request: GatewayCommandResultRequest,
        http_request: Request,
    ) -> dict[str, object]:
        command = store.get_gateway_command(command_id)
        if command is None or command["gateway_id"] != gateway_id:
            raise HTTPException(status_code=404, detail="Gateway command not found")
        if store.get_integration_secret(gateway_id) and not gateway_token_valid(http_request):
            raise HTTPException(status_code=401, detail="Gateway authentication required")
        try:
            return process_gateway_command_result(
                store, command_id, request.status, request.result,
            )
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @router.get("/api/v1/gateways", tags=["gateway"])
    def list_gateways() -> list[dict[str, object]]:
        return gateway_connections.list_status()

    @router.get("/api/v1/gateways/{gateway_id}", tags=["gateway"])
    def get_gateway_status(gateway_id: str) -> dict[str, object]:
        gateway = gateway_connections.get_status(gateway_id)
        if gateway is None:
            raise HTTPException(status_code=404, detail="Gateway not found")
        return gateway

    return router
