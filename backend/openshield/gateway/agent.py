import hashlib
import json
import logging
import os
import time
from datetime import UTC, datetime
from uuid import uuid4

from openshield.events.models import EventEnvelope, EventSource, Severity
from openshield.gateway.client import GatewayConnectorClient, GatewayTransportError
from openshield.gateway.spool import GatewayEventSpool, SpoolFullError
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


def _flush_spool(
    client: GatewayConnectorClient,
    spool: GatewayEventSpool,
) -> bool:
    while pending := spool.pending():
        for event in pending:
            try:
                client.ingest_event(event)
            except GatewayTransportError as exc:
                logger.warning("Gateway event delivery deferred: %s", exc)
                return False
            spool.acknowledge(event.event_id)
    return True


def _queue_event(spool: GatewayEventSpool, event: EventEnvelope) -> bool:
    try:
        spool.enqueue(event)
    except SpoolFullError as exc:
        logger.error("Gateway event spool is full: %s", exc)
        return False
    return True


def _deliver_event(
    client: GatewayConnectorClient,
    event: EventEnvelope,
    spool: GatewayEventSpool | None,
) -> bool:
    if spool is None:
        try:
            client.ingest_event(event)
        except GatewayTransportError as exc:
            logger.warning("Gateway event delivery failed: %s", exc)
            return False
        return True
    if not _queue_event(spool, event):
        return False
    return _flush_spool(client, spool)


def _collect_while_node_unavailable(
    openwrt_client: OpenWrtRPCClient,
    integration_id: str,
    spool: GatewayEventSpool,
    include_discovery: bool,
) -> None:
    if include_discovery:
        try:
            _queue_event(
                spool,
                _event(integration_id, "gateway.discovery", openwrt_client.discover()),
            )
        except OpenWrtRPCError as exc:
            logger.warning("OpenWrt discovery failed while Node is unavailable: %s", exc)
    try:
        health = openwrt_client.health_check()
        _queue_event(spool, _event(integration_id, "gateway.health", health))
    except OpenWrtRPCError as exc:
        logger.warning("OpenWrt health check failed while Node is unavailable: %s", exc)
        _queue_event(
            spool,
            _event(
                integration_id,
                "gateway.health",
                {"status": "unavailable", "reason": "rpc_unavailable"},
                Severity.MEDIUM,
            ),
        )


def _configured_openwrt_client(config: object) -> OpenWrtRPCClient | None:
    if config is None:
        return None
    if not isinstance(config, dict):
        logger.error("Node returned invalid OpenWrt connector configuration")
        return None
    base_url = config.get("base_url")
    username = config.get("username")
    password = config.get("password")
    if not all(isinstance(value, str) and value for value in (base_url, username, password)):
        logger.error("Node returned incomplete OpenWrt connector configuration")
        return None
    try:
        return OpenWrtRPCClient(base_url, username, password)
    except ValueError:
        logger.error("Node returned invalid OpenWrt connector configuration")
        return None


def _openwrt_config_signature(config: object) -> str | None:
    if not isinstance(config, dict):
        return None
    encoded = json.dumps(config, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def run_agent(
    client: GatewayConnectorClient,
    heartbeat_interval: float = 30.0,
    openwrt_client: OpenWrtRPCClient | None = None,
    integration_id: str | None = None,
    spool: GatewayEventSpool | None = None,
) -> None:
    if not 5 <= heartbeat_interval <= 60:
        raise ValueError("Heartbeat interval must be between 5 and 60 seconds")
    if openwrt_client is not None and integration_id is None:
        raise ValueError("Integration ID is required when an OpenWrt client is configured")

    retry_delay = 1.0
    discovery_collected_offline = False
    openwrt_config_signature: str | None = None
    while True:
        try:
            result = client.connect()
            if "openwrt_config" in result:
                openwrt_config_signature = _openwrt_config_signature(result["openwrt_config"])
                openwrt_client = _configured_openwrt_client(result["openwrt_config"])
                if integration_id is None:
                    integration_id = str(result.get("gateway_id") or "")
            logger.info("Gateway connected", extra={"gateway_id": result.get("gateway_id")})
            retry_delay = 1.0
        except GatewayTransportError as exc:
            logger.warning("Gateway connection failed: %s", exc)
            if (
                openwrt_client is not None
                and integration_id is not None
                and spool is not None
            ):
                _collect_while_node_unavailable(
                    openwrt_client,
                    integration_id,
                    spool,
                    include_discovery=not discovery_collected_offline,
                )
                discovery_collected_offline = True
            time.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, 60.0)
            continue

        if spool is not None:
            _flush_spool(client, spool)

        if openwrt_client is not None and integration_id is not None:
            try:
                discovery = openwrt_client.discover()
                _deliver_event(
                    client,
                    _event(integration_id, "gateway.discovery", discovery),
                    spool,
                )
            except OpenWrtRPCError as exc:
                logger.warning("OpenWrt discovery failed: %s", exc)

        while True:
            time.sleep(heartbeat_interval)
            try:
                heartbeat = client.heartbeat()
                if "openwrt_config" in heartbeat:
                    signature = _openwrt_config_signature(heartbeat["openwrt_config"])
                    if signature != openwrt_config_signature:
                        openwrt_config_signature = signature
                        openwrt_client = _configured_openwrt_client(heartbeat["openwrt_config"])
                        if integration_id is None:
                            integration_id = str(heartbeat.get("gateway_id") or "")
                        if openwrt_client is not None and integration_id:
                            discovery = openwrt_client.discover()
                            _deliver_event(
                                client,
                                _event(integration_id, "gateway.discovery", discovery),
                                spool,
                            )
                if spool is not None:
                    _flush_spool(client, spool)
                if openwrt_client is not None and integration_id is not None:
                    try:
                        discovery = openwrt_client.discover()
                        _deliver_event(
                            client,
                            _event(integration_id, "gateway.discovery", discovery),
                            spool,
                        )
                    except OpenWrtRPCError as exc:
                        logger.warning("OpenWrt device discovery failed: %s", exc)
                    health = openwrt_client.health_check()
                    _deliver_event(
                        client,
                        _event(integration_id, "gateway.health", health),
                        spool,
                    )
            except OpenWrtRPCError as exc:
                logger.warning("OpenWrt health check failed: %s", exc)
                if integration_id is not None:
                    _deliver_event(
                        client,
                        _event(
                            integration_id,
                            "gateway.health",
                            {"status": "unavailable", "reason": "rpc_unavailable"},
                            Severity.MEDIUM,
                        ),
                        spool,
                    )
            except GatewayTransportError as exc:
                logger.warning("Gateway heartbeat failed; reconnecting: %s", exc)
                break


def main() -> None:
    logging.basicConfig(
        level=os.getenv("OPENSHIELD_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    node_url = os.getenv("OPENSHIELD_NODE_URL", "").strip()
    gateway_id = os.getenv("OPENSHIELD_GATEWAY_ID", "").strip()
    gateway_id = gateway_id or "home-gateway"
    if not node_url:
        raise SystemExit("OPENSHIELD_NODE_URL is required")
    try:
        interval = float(os.getenv("OPENSHIELD_GATEWAY_HEARTBEAT_INTERVAL", "30"))
    except ValueError as exc:
        raise SystemExit("OPENSHIELD_GATEWAY_HEARTBEAT_INTERVAL must be numeric") from exc

    openwrt_url = os.getenv("OPENSHIELD_OPENWRT_URL", "").strip()
    openwrt_username = os.getenv("OPENSHIELD_OPENWRT_USERNAME", "")
    openwrt_password = os.getenv("OPENSHIELD_OPENWRT_PASSWORD", "")
    integration_id = gateway_id
    openwrt_values = (openwrt_url, openwrt_username, openwrt_password)
    if any(openwrt_values) and not all(openwrt_values):
        raise SystemExit(
            "OPENSHIELD_OPENWRT_URL, OPENSHIELD_OPENWRT_USERNAME, and "
            "OPENSHIELD_OPENWRT_PASSWORD must be configured together"
        )
    openwrt_client = None
    capabilities = [Capability.DISCOVER, Capability.HEALTH_CHECK]
    if all(openwrt_values):
        openwrt_client = OpenWrtRPCClient(
            base_url=openwrt_url,
            username=openwrt_username,
            password=openwrt_password,
        )

    spool = GatewayEventSpool(
        os.getenv(
            "OPENSHIELD_GATEWAY_SPOOL_PATH",
            "/var/lib/openshield/gateway-spool.sqlite3",
        )
    )
    client = GatewayConnectorClient(
        node_url=node_url,
        gateway_id=gateway_id,
        connector_version=os.getenv("OPENSHIELD_GATEWAY_CONNECTOR_VERSION", "0.1.0"),
        capabilities=capabilities,
        gateway_token=os.getenv("OPENSHIELD_GATEWAY_TOKEN", ""),
    )
    try:
        run_agent(
            client,
            heartbeat_interval=interval,
            openwrt_client=openwrt_client,
            integration_id=integration_id,
            spool=spool,
        )
    except KeyboardInterrupt:
        logger.info("Gateway connector stopped")


if __name__ == "__main__":
    main()
