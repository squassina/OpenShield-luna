from datetime import UTC, datetime, timedelta

from openshield.core.storage import PostgresStore
from openshield.gateway.models import GatewayConnection, GatewayConnectRequest

CONNECTION_TIMEOUT = timedelta(seconds=90)


class GatewayConnectionRegistry:
    """Gateway presence registry; persistence never controls packet forwarding."""

    def __init__(self, store: PostgresStore | None = None) -> None:
        self._store = store
        self._connections: dict[str, GatewayConnection] = {}

    def connect(self, request: GatewayConnectRequest) -> GatewayConnection:
        connection = GatewayConnection.create(request)
        if self._store is not None:
            self._store.connect_gateway(connection)
        else:
            self._connections[connection.gateway_id] = connection
        return connection

    def heartbeat(self, gateway_id: str) -> GatewayConnection | None:
        if self._store is not None:
            return self._store.heartbeat_gateway(gateway_id)
        connection = self._connections.get(gateway_id)
        if connection is None:
            return None
        updated = connection.model_copy(update={"last_seen_at": datetime.now(UTC)})
        self._connections[gateway_id] = updated
        return updated

    def get_status(self, gateway_id: str) -> dict[str, object] | None:
        connection = (
            self._store.get_gateway(gateway_id)
            if self._store is not None
            else self._connections.get(gateway_id)
        )
        if connection is None:
            return None
        connected = datetime.now(UTC) - connection.last_seen_at <= CONNECTION_TIMEOUT
        return {
            **connection.model_dump(mode="json"),
            "status": "connected" if connected else "stale",
        }

    def list_status(self) -> list[dict[str, object]]:
        connections = (
            self._store.list_gateways()
            if self._store is not None
            else list(self._connections.values())
        )
        now = datetime.now(UTC)
        return [
            {
                **connection.model_dump(mode="json"),
                "status": (
                    "connected"
                    if now - connection.last_seen_at <= CONNECTION_TIMEOUT
                    else "stale"
                ),
            }
            for connection in connections
        ]
