import logging
import os
import time
from datetime import UTC, datetime
from uuid import uuid4

from openshield.events.models import EventEnvelope, EventSource, Severity
from openshield.gateway.client import GatewayConnectorClient, GatewayTransportError
from openshield.integrations.models import Capability
from openshield.integrations.openwrt_rpc import OpenWrtRPCClient, OpenWrtRPCError

logger = logging.getLogger("openshield.gateway.agent")


def _event(
    integration_id: str,
    event_type: str,
    payload: dict[str, object],
    severity: Severity = Severity.INFO,
) -> EventEnvelope:
    now = datetime.now(UTC)
    return EventEnvelope(
        schema_version="openshield.event.v1",
        event_id=str(uuid4()),
        source=EventSource(integration_id=integration_id, kind="openwrt"),
        event_type=event_type,
        occurred_at=now,
        observed_at=now,
        severity=severity,
        payload=payload,
    )


def run_agent(
    client: GatewayConnectorClient,
    heartbeat_interval: float = 30.0,
    openwrt_client: OpenWrtRPCClient | None = None,
    integration_id: str | None = None,
) -> None:
    if not 5 <= heartbeat_interval <= 60:
        raise ValueError("Heartbeat interval must be between 5 and 60 seconds")
    if (openwrt_client is None) != (integration_id is None):
        raise ValueError("OpenWrt client and integration ID must be configured together")

    retry_delay = 1.0
    while True:
        try:
            result = client.connect()
            logger.info("Gateway connected", extra={"gateway_id": result.get("gateway_id")})
            retry_delay = 1.0
        except GatewayTransportError as exc:
            logger.warning("Gateway connection failed: %s", exc)
            time.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, 60.0)
            continue

        if openwrt_client is not None and integration_id is not None:
            try:
                discovery = openwrt_client.discover()
                client.ingest_event(
                    _event(integration_id, "gateway.discovery", discovery)
                )
            except OpenWrtRPCError as exc:
                logger.warning("OpenWrt discovery failed: %s", exc)
            except GatewayTransportError as exc:
                logger.warning("Unable to send gateway discovery to Node: %s", exc)
                break

        while True:
            time.sleep(heartbeat_interval)
            try:
                client.heartbeat()
                if openwrt_client is not None and integration_id is not None:
                    health = openwrt_client.health_check()
                    client.ingest_event(
                        _event(integration_id, "gateway.health", health)
                    )
            except OpenWrtRPCError as exc:
                logger.warning("OpenWrt health check failed: %s", exc)
                if integration_id is not None:
                    try:
                        client.ingest_event(
                            _event(
                                integration_id,
                                "gateway.health",
                                {"status": "unavailable", "reason": "rpc_unavailable"},
                                Severity.MEDIUM,
                            )
                        )
                    except GatewayTransportError as transport_exc:
                        logger.warning("Unable to send gateway health event: %s", transport_exc)
                        break
            except GatewayTransportError as exc:
                logger.warning("Gateway heartbeat or event delivery failed; reconnecting: %s", exc)
                break


def main() -> None:
    logging.basicConfig(
        level=os.getenv("OPENSHIELD_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    node_url = os.getenv("OPENSHIELD_NODE_URL", "").strip()
    gateway_id = os.getenv("OPENSHIELD_GATEWAY_ID", "").strip()
    api_key = os.getenv("OPENSHIELD_GATEWAY_API_KEY", "")
    if not node_url or not gateway_id or not api_key:
        raise SystemExit(
            "OPENSHIELD_NODE_URL, OPENSHIELD_GATEWAY_ID, and "
            "OPENSHIELD_GATEWAY_API_KEY are required"
        )
    try:
        interval = float(os.getenv("OPENSHIELD_GATEWAY_HEARTBEAT_INTERVAL", "30"))
    except ValueError as exc:
        raise SystemExit("OPENSHIELD_GATEWAY_HEARTBEAT_INTERVAL must be numeric") from exc

    openwrt_url = os.getenv("OPENSHIELD_OPENWRT_URL", "").strip()
    openwrt_username = os.getenv("OPENSHIELD_OPENWRT_USERNAME", "")
    openwrt_password = os.getenv("OPENSHIELD_OPENWRT_PASSWORD", "")
    integration_id = os.getenv("OPENSHIELD_INTEGRATION_ID", "").strip()
    openwrt_values = (openwrt_url, openwrt_username, openwrt_password, integration_id)
    if any(openwrt_values) and not all(openwrt_values):
        raise SystemExit(
            "OPENSHIELD_OPENWRT_URL, OPENSHIELD_OPENWRT_USERNAME, "
            "OPENSHIELD_OPENWRT_PASSWORD, and OPENSHIELD_INTEGRATION_ID "
            "must be configured together"
        )

    openwrt_client = None
    capabilities = []
    if all(openwrt_values):
        openwrt_client = OpenWrtRPCClient(
            base_url=openwrt_url,
            username=openwrt_username,
            password=openwrt_password,
        )
        capabilities = [Capability.DISCOVER, Capability.HEALTH_CHECK]

    client = GatewayConnectorClient(
        node_url=node_url,
        gateway_id=gateway_id,
        api_key=api_key,
        connector_version=os.getenv("OPENSHIELD_GATEWAY_CONNECTOR_VERSION", "0.1.0"),
        capabilities=capabilities,
    )
    try:
        run_agent(
            client,
            heartbeat_interval=interval,
            openwrt_client=openwrt_client,
            integration_id=integration_id or None,
        )
    except KeyboardInterrupt:
        logger.info("Gateway connector stopped")


if __name__ == "__main__":
    main()
