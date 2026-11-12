import threading
from datetime import UTC, datetime

import psycopg
from psycopg.types.json import Jsonb

from openshield.events.models import EventEnvelope
from openshield.gateway.models import GatewayConnection
from openshield.integrations.models import Integration


class StorageConfigurationError(RuntimeError):
    pass


class PostgresStore:
    """Small synchronous PostgreSQL store for P0 state and event persistence."""

    def __init__(self, dsn: str) -> None:
        self._dsn = dsn.strip()
        self._schema_ready = False
        self._schema_lock = threading.Lock()

    def _connect(self) -> psycopg.Connection:
        if not self._dsn:
            raise StorageConfigurationError("OPENSHIELD_DATABASE_URL is required")
        self.ensure_schema()
        return psycopg.connect(self._dsn, connect_timeout=5)

    def ensure_schema(self) -> None:
        if self._schema_ready:
            return
        if not self._dsn:
            raise StorageConfigurationError("OPENSHIELD_DATABASE_URL is required")
        with self._schema_lock:
            if self._schema_ready:
                return
            statements = [
                """
                CREATE TABLE IF NOT EXISTS integrations (
                    integration_id TEXT PRIMARY KEY,
                    payload JSONB NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    payload JSONB NOT NULL,
                    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS gateway_connections (
                    gateway_id TEXT PRIMARY KEY,
                    payload JSONB NOT NULL,
                    connected_at TIMESTAMPTZ NOT NULL,
                    last_seen_at TIMESTAMPTZ NOT NULL
                )
                """,
            ]
            with psycopg.connect(self._dsn, connect_timeout=5) as connection:
                with connection.cursor() as cursor:
                    for statement in statements:
                        cursor.execute(statement)
            self._schema_ready = True

    def is_ready(self) -> bool:
        try:
            with self._connect() as connection:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT 1")
                    return cursor.fetchone() == (1,)
        except (psycopg.Error, StorageConfigurationError):
            return False

    def reset(self) -> None:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "TRUNCATE TABLE events, gateway_connections, integrations"
                )

    def insert_integration(self, integration: Integration) -> None:
        payload = integration.model_dump(mode="json")
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO integrations (integration_id, payload)
                    VALUES (%s, %s)
                    ON CONFLICT (integration_id) DO NOTHING
                    RETURNING integration_id
                    """,
                    (integration.integration_id, Jsonb(payload)),
                )
                if cursor.fetchone() is None:
                    raise ValueError("Integration already exists")

    def get_integration(self, integration_id: str) -> Integration | None:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT payload FROM integrations WHERE integration_id = %s",
                    (integration_id,),
                )
                row = cursor.fetchone()
        return Integration.model_validate(row[0]) if row else None

    def list_integrations(self) -> list[Integration]:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT payload FROM integrations ORDER BY integration_id"
                )
                rows = cursor.fetchall()
        return [Integration.model_validate(row[0]) for row in rows]

    def insert_event(self, event: EventEnvelope) -> None:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO events (event_id, payload)
                    VALUES (%s, %s)
                    ON CONFLICT (event_id) DO NOTHING
                    RETURNING event_id
                    """,
                    (event.event_id, Jsonb(event.model_dump(mode="json"))),
                )
                if cursor.fetchone() is None:
                    raise ValueError("Event already exists")

    def list_events(self) -> list[EventEnvelope]:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT payload FROM events ORDER BY received_at, event_id"
                )
                rows = cursor.fetchall()
        return [EventEnvelope.model_validate(row[0]) for row in rows]

    def connect_gateway(self, gateway: GatewayConnection) -> None:
        payload = gateway.model_dump(mode="json")
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO gateway_connections
                        (gateway_id, payload, connected_at, last_seen_at)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (gateway_id) DO UPDATE SET
                        payload = EXCLUDED.payload,
                        connected_at = EXCLUDED.connected_at,
                        last_seen_at = EXCLUDED.last_seen_at
                    """,
                    (
                        gateway.gateway_id,
                        Jsonb(payload),
                        gateway.connected_at,
                        gateway.last_seen_at,
                    ),
                )

    def heartbeat_gateway(self, gateway_id: str) -> GatewayConnection | None:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT payload FROM gateway_connections WHERE gateway_id = %s",
                    (gateway_id,),
                )
                row = cursor.fetchone()
                if row is None:
                    return None
                current = GatewayConnection.model_validate(row[0])
                updated = current.model_copy(update={"last_seen_at": datetime.now(UTC)})
                cursor.execute(
                    """
                    UPDATE gateway_connections
                    SET payload = %s, last_seen_at = %s
                    WHERE gateway_id = %s
                    """,
                    (
                        Jsonb(updated.model_dump(mode="json")),
                        updated.last_seen_at,
                        gateway_id,
                    ),
                )
        return updated

    def get_gateway(self, gateway_id: str) -> GatewayConnection | None:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT payload FROM gateway_connections WHERE gateway_id = %s",
                    (gateway_id,),
                )
                row = cursor.fetchone()
        return GatewayConnection.model_validate(row[0]) if row else None

    def list_gateways(self) -> list[GatewayConnection]:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT payload FROM gateway_connections ORDER BY gateway_id"
                )
                rows = cursor.fetchall()
        return [GatewayConnection.model_validate(row[0]) for row in rows]
