import logging
import os
import time

from openshield.gateway.client import GatewayConnectorClient, GatewayTransportError

logger = logging.getLogger("openshield.gateway.agent")


def run_agent(
    client: GatewayConnectorClient,
    heartbeat_interval: float = 30.0,
) -> None:
    if not 5 <= heartbeat_interval <= 60:
        raise ValueError("Heartbeat interval must be between 5 and 60 seconds")

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

        while True:
            time.sleep(heartbeat_interval)
            try:
                client.heartbeat()
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

    client = GatewayConnectorClient(
        node_url=node_url,
        gateway_id=gateway_id,
        api_key=api_key,
        connector_version=os.getenv("OPENSHIELD_GATEWAY_CONNECTOR_VERSION", "0.1.0"),
    )
    try:
        run_agent(client, heartbeat_interval=interval)
    except KeyboardInterrupt:
        logger.info("Gateway connector stopped")


if __name__ == "__main__":
    main()
