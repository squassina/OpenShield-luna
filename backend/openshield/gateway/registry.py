from datetime import UTC, datetime, timedelta

from openshield.gateway.models import GatewayConnectRequest, GatewayConnection
from openshield.integrations.models import Capability

CONNECTION_TIMEOUT = timedelta(seconds=90)


class GatewayConnectionRegistry:
    """In-memory gateway presence registry; it never controls packet forwarding."""

    def __init__(self) -> None:
        self._connections: dict[str, GatewayConnection] = {}

    def connect(self, request: GatewayConnectRequest) -> GatewayConnection:
        connection = GatewayConnection.create(request)
        self._connections[connection.gateway_id] = connection
        return connection

    def heartbeat(self, gateway_id: str) -> GatewayConnection | None:
        connection = self._connections.get(gateway_id)
        if connection is None:
            return None
        updated = connection.model_copy(update={"last_seen_at": datetime.now(UTC)})
        self._connections[gateway_id] = updated
        return updated

    def get_status(self, gateway_id: str) -> dict[str, object] | None:
        connection = self._connections.get(gateway_id)
        if connection is None:
            return None
        connected = datetime.now(UTC) - connection.last_seen_at <= CONNECTION_TIMEOUT
        return {
            **connection.model_dump(mode="json"),
            "status": "connected" if connected else "stale",
        }

    def list_status(self) -> list[dict[str, object]]:
        return [
            status
            for gateway_id in self._connections
            if (status := self.get_status(gateway_id)) is not None
        ]
