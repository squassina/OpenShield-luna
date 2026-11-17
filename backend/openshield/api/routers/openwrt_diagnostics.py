from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException

from openshield.core.storage import PostgresStore
from openshield.gateway.registry import GatewayConnectionRegistry
from openshield.integrations.registry import IntegrationRegistry


def create_openwrt_diagnostics_router(
    *,
    store: PostgresStore,
    registry: IntegrationRegistry,
    gateway_connections: GatewayConnectionRegistry,
) -> APIRouter:
    router = APIRouter()

    @router.get("/api/v1/integrations/{integration_id}/test", tags=["integrations"])
    def test_openwrt_connector(integration_id: str) -> dict[str, object]:
        integration = registry.get(integration_id)
        if integration is None or integration.kind != "openwrt":
            raise HTTPException(status_code=404, detail="OpenWrt integration not found")
        if not integration.config.get("rpc_configured"):
            raise HTTPException(status_code=409, detail="OpenWrt credentials are not configured")
        gateway = gateway_connections.get_status(integration_id)
        if gateway is None or gateway.get("status") != "connected":
            return {
                "status": "connector_disconnected",
                "message": "Gateway Connector is not connected. Check its deployment and OPENSHIELD_GATEWAY_TOKEN.",
            }
        health_events = store.list_events(integration_id, "gateway.health", limit=1)
        discovery_events = store.list_events(integration_id, "gateway.discovery", limit=1)
        discovery = discovery_events[0] if discovery_events else None
        router_info = discovery.payload if discovery else None
        last_discovery = discovery.observed_at.isoformat() if discovery else None
        if health_events:
            health = health_events[0]
            age_seconds = max(0, int((datetime.now(UTC) - health.observed_at).total_seconds()))
            diagnostics = {
                "last_rpc_check": health.observed_at.isoformat(),
                "last_rpc_check_age_seconds": age_seconds,
                "last_discovery_at": last_discovery,
                "router": router_info,
                "gateway": gateway,
            }
            if health.payload.get("status") == "reachable":
                if age_seconds > 90:
                    return {
                        "status": "router_rpc_stale",
                        "message": "The last successful OpenWrt RPC check is older than 90 seconds. Check connector heartbeat and router reachability.",
                        **diagnostics,
                    }
                return {
                    "status": "router_rpc_connected",
                    "message": "Gateway Connector and OpenWrt RPC are responding.",
                    **diagnostics,
                }
            if health.payload.get("status") == "unavailable":
                return {
                    "status": "router_rpc_failed",
                    "message": "Gateway Connector is online but OpenWrt RPC failed. Check router URL, RPC credentials, read-only rpcd ACL permissions and TLS trust.",
                    **diagnostics,
                }
        return {
            "status": "connector_connected",
            "message": "Gateway Connector is online. Waiting for its first OpenWrt RPC health check.",
            "last_discovery_at": last_discovery,
            "router": router_info,
            "gateway": gateway,
        }

    return router
