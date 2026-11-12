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
                CREATE INDEX IF NOT EXISTS events_received_at_idx
                ON events (received_at DESC)
                """,
                """
                CREATE INDEX IF NOT EXISTS events_source_integration_idx
                ON events ((payload #>> '{source,integration_id}'))
                """,
                """
                CREATE INDEX IF NOT EXISTS events_event_type_idx
                ON events ((payload->>'event_type'))
                """,
                """
                CREATE INDEX IF NOT EXISTS events_severity_idx
                ON events ((payload->>'severity'))
                """,
                """
                CREATE TABLE IF NOT EXISTS privacy_lists (
                    integration_id TEXT NOT NULL,
                    list_type TEXT NOT NULL CHECK (list_type IN ('allow', 'block')),
                    domain TEXT NOT NULL,
                    comment TEXT NOT NULL DEFAULT '',
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    PRIMARY KEY (integration_id, list_type, domain)
                )
                """,
                """
                CREATE INDEX IF NOT EXISTS privacy_lists_domain_idx
                ON privacy_lists (domain)
                """,
                """
                CREATE TABLE IF NOT EXISTS gateway_connections (
                    gateway_id TEXT PRIMARY KEY,
                    payload JSONB NOT NULL,
                    connected_at TIMESTAMPTZ NOT NULL,
                    last_seen_at TIMESTAMPTZ NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS audit_records (
                    audit_id BIGSERIAL PRIMARY KEY,
                    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    actor_id TEXT,
                    action TEXT NOT NULL,
                    target_id TEXT,
                    details JSONB NOT NULL DEFAULT '{}'::jsonb
                )
                """,
                """
                CREATE INDEX IF NOT EXISTS audit_records_occurred_at_idx
                ON audit_records (occurred_at DESC)
                """,
            ]
            with (
                psycopg.connect(self._dsn, connect_timeout=5) as connection,
                connection.cursor() as cursor,
            ):
                for statement in statements:
                    cursor.execute(statement)
            self._schema_ready = True

    def is_ready(self) -> bool:
        try:
            with self._connect() as connection, connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                return cursor.fetchone() == (1,)
        except (psycopg.Error, StorageConfigurationError):
            return False

    def reset(self) -> None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "TRUNCATE TABLE audit_records, events, privacy_lists, gateway_connections, integrations RESTART IDENTITY"
            )

    def insert_integration(
        self, integration: Integration, actor_id: str | None = None
    ) -> None:
        payload = integration.model_dump(mode="json")
        with self._connect() as connection, connection.cursor() as cursor:
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
            self._insert_audit(
                cursor,
                "integration.registered",
                actor_id,
                integration.integration_id,
                {
                    "kind": integration.kind,
                    "capabilities": [item.value for item in integration.capabilities],
                },
            )

    def get_integration(self, integration_id: str) -> Integration | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT payload FROM integrations WHERE integration_id = %s",
                (integration_id,),
            )
            row = cursor.fetchone()
        return Integration.model_validate(row[0]) if row else None

    def list_integrations(self) -> list[Integration]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT payload FROM integrations ORDER BY integration_id"
            )
            rows = cursor.fetchall()
        return [Integration.model_validate(row[0]) for row in rows]

    def insert_event(self, event: EventEnvelope, actor_id: str | None = None) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
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
                return False
            self._insert_audit(
                cursor,
                "event.ingested",
                actor_id,
                event.event_id,
                {
                    "event_type": event.event_type,
                    "severity": event.severity.value,
                    "source_integration_id": event.source.integration_id,
                },
            )
        return True

    def list_events(
        self,
        integration_id: str | None = None,
        event_type: str | None = None,
        severity: str | None = None,
        limit: int = 1000,
    ) -> list[EventEnvelope]:
        filters = []
        params: list[object] = []
        if integration_id:
            filters.append("payload #>> '{source,integration_id}' = %s")
            params.append(integration_id)
        if event_type:
            filters.append("payload->>'event_type' = %s")
            params.append(event_type)
        if severity:
            filters.append("payload->>'severity' = %s")
            params.append(severity)
        where = f"WHERE {' AND '.join(filters)}" if filters else ""
        params.append(limit)
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                f"SELECT payload FROM events {where} ORDER BY received_at DESC, event_id LIMIT %s",
                params,
            )
            rows = cursor.fetchall()
        return [EventEnvelope.model_validate(row[0]) for row in rows]

    def list_inventory_observations(self, limit: int = 2000) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                WITH observations AS (
                    SELECT
                        COALESCE(payload #>> '{payload,src_ip}', payload #>> '{payload,id.orig_h}') AS address,
                        (payload->>'occurred_at')::timestamptz AS occurred_at,
                        COALESCE(payload #>> '{payload,proto}', payload #>> '{payload,app_proto}', 'unknown') AS protocol
                    FROM events
                    UNION ALL
                    SELECT
                        COALESCE(payload #>> '{payload,dest_ip}', payload #>> '{payload,id.resp_h}') AS address,
                        (payload->>'occurred_at')::timestamptz AS occurred_at,
                        COALESCE(payload #>> '{payload,proto}', payload #>> '{payload,app_proto}', 'unknown') AS protocol
                    FROM events
                )
                SELECT address, MIN(occurred_at), MAX(occurred_at),
                       COUNT(*), ARRAY_AGG(DISTINCT protocol)
                FROM observations
                WHERE address IS NOT NULL
                GROUP BY address
                ORDER BY COUNT(*) DESC, address
                LIMIT %s
                """,
                (limit,),
            )
            rows = cursor.fetchall()
        return [
            {
                "ip_address": row[0], "first_seen": row[1], "last_seen": row[2],
                "observations": row[3], "protocols": row[4],
            }
            for row in rows
        ]

    def list_topology_observations(self, limit: int = 5000) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                WITH connections AS (
                    SELECT
                        COALESCE(payload #>> '{payload,src_ip}', payload #>> '{payload,id.orig_h}') AS source,
                        COALESCE(payload #>> '{payload,dest_ip}', payload #>> '{payload,id.resp_h}') AS target,
                        COALESCE(payload #>> '{payload,proto}', payload #>> '{payload,app_proto}', 'unknown') AS protocol
                    FROM events
                )
                SELECT source, target, protocol, COUNT(*)
                FROM connections
                WHERE source IS NOT NULL AND target IS NOT NULL
                GROUP BY source, target, protocol
                ORDER BY COUNT(*) DESC, source, target
                LIMIT %s
                """,
                (limit,),
            )
            rows = cursor.fetchall()
        return [
            {"source": row[0], "target": row[1], "protocol": row[2], "observations": row[3]}
            for row in rows
        ]

    def sensor_event_stats(self) -> dict[str, dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    payload #>> '{source,integration_id}' AS integration_id,
                    COUNT(*) AS events_seen,
                    MAX((payload->>'observed_at')::timestamptz) AS last_observed_at
                FROM events
                WHERE payload #>> '{source,kind}' IN ('suricata', 'zeek')
                GROUP BY payload #>> '{source,integration_id}'
                """
            )
            rows = cursor.fetchall()
        return {
            row[0]: {"events_seen": row[1], "last_observed_at": row[2]}
            for row in rows
        }

    def privacy_domain_stats(self, days: int = 30, limit: int = 100) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT payload #>> '{payload,domain}', COUNT(*),
                       COUNT(*) FILTER (WHERE payload #>> '{payload,status}' = 'blocked'),
                       COUNT(*) FILTER (WHERE payload #>> '{payload,category}' = 'tracker'),
                       COUNT(DISTINCT payload #>> '{payload,client}'),
                       MAX((payload->>'observed_at')::timestamptz)
                FROM events
                WHERE payload->>'event_type' = 'privacy.dns.query'
                  AND (payload->>'occurred_at')::timestamptz >= NOW() - (%s * INTERVAL '1 day')
                GROUP BY payload #>> '{payload,domain}'
                ORDER BY COUNT(*) DESC, payload #>> '{payload,domain}'
                LIMIT %s
                """,
                (days, limit),
            )
            rows = cursor.fetchall()
        return [
            {"domain": r[0], "queries": r[1], "blocked": r[2], "tracker_queries": r[3],
             "unique_clients": r[4], "last_seen": r[5].isoformat() if r[5] else None}
            for r in rows
        ]

    def privacy_client_stats(self, days: int = 30, limit: int = 100) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT COALESCE(payload #>> '{payload,client}', 'unknown'), COUNT(*),
                       COUNT(DISTINCT payload #>> '{payload,domain}'),
                       COUNT(*) FILTER (WHERE payload #>> '{payload,status}' = 'blocked'),
                       COUNT(*) FILTER (WHERE payload #>> '{payload,category}' = 'tracker')
                FROM events
                WHERE payload->>'event_type' = 'privacy.dns.query'
                  AND (payload->>'occurred_at')::timestamptz >= NOW() - (%s * INTERVAL '1 day')
                GROUP BY COALESCE(payload #>> '{payload,client}', 'unknown')
                ORDER BY COUNT(*) DESC
                LIMIT %s
                """,
                (days, limit),
            )
            rows = cursor.fetchall()
        return [
            {"client": r[0], "queries": r[1], "unique_domains": r[2],
             "blocked": r[3], "tracker_queries": r[4]}
            for r in rows
        ]

    def privacy_trends(self, days: int = 30) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT date_trunc('day', (payload->>'occurred_at')::timestamptz)::date,
                       COUNT(*),
                       COUNT(*) FILTER (WHERE payload #>> '{payload,status}' = 'blocked'),
                       COUNT(*) FILTER (WHERE payload #>> '{payload,category}' = 'tracker'),
                       COUNT(DISTINCT payload #>> '{payload,domain}')
                FROM events
                WHERE payload->>'event_type' = 'privacy.dns.query'
                  AND (payload->>'occurred_at')::timestamptz >= NOW() - (%s * INTERVAL '1 day')
                GROUP BY 1 ORDER BY 1
                """,
                (days,),
            )
            rows = cursor.fetchall()
        return [
            {"date": r[0].isoformat(), "queries": r[1], "blocked": r[2],
             "tracker_queries": r[3], "unique_domains": r[4]}
            for r in rows
        ]

    def upsert_privacy_list(
        self, integration_id: str, list_type: str, domain: str, comment: str = ""
    ) -> None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO privacy_lists (integration_id, list_type, domain, comment)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (integration_id, list_type, domain)
                DO UPDATE SET comment = EXCLUDED.comment, updated_at = NOW()
                """,
                (integration_id, list_type, domain, comment),
            )
            self._insert_audit(cursor, "privacy.list.updated", None, domain,
                               {"integration_id": integration_id, "list_type": list_type})

    def list_privacy_lists(self, integration_id: str | None = None) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            if integration_id:
                cursor.execute(
                    "SELECT integration_id, list_type, domain, comment, updated_at FROM privacy_lists WHERE integration_id = %s ORDER BY list_type, domain",
                    (integration_id,),
                )
            else:
                cursor.execute(
                    "SELECT integration_id, list_type, domain, comment, updated_at FROM privacy_lists ORDER BY integration_id, list_type, domain"
                )
            rows = cursor.fetchall()
        return [
            {"integration_id": r[0], "list_type": r[1], "domain": r[2],
             "comment": r[3], "updated_at": r[4].isoformat()}
            for r in rows
        ]

    def delete_privacy_list_item(self, integration_id: str, list_type: str, domain: str) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM privacy_lists WHERE integration_id = %s AND list_type = %s AND domain = %s RETURNING domain",
                (integration_id, list_type, domain),
            )
            deleted = cursor.fetchone() is not None
            if deleted:
                self._insert_audit(cursor, "privacy.list.deleted", None, domain,
                                   {"integration_id": integration_id, "list_type": list_type})
        return deleted

    def connect_gateway(
        self, gateway: GatewayConnection, actor_id: str | None = None
    ) -> None:
        payload = gateway.model_dump(mode="json")
        with self._connect() as connection, connection.cursor() as cursor:
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
            self._insert_audit(
                cursor,
                "gateway.connected",
                actor_id,
                gateway.gateway_id,
                {
                    "gateway_type": gateway.gateway_type,
                    "connector_version": gateway.connector_version,
                    "capabilities": [item.value for item in gateway.capabilities],
                },
            )

    def heartbeat_gateway(self, gateway_id: str) -> GatewayConnection | None:
        with self._connect() as connection, connection.cursor() as cursor:
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
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT payload FROM gateway_connections WHERE gateway_id = %s",
                (gateway_id,),
            )
            row = cursor.fetchone()
        return GatewayConnection.model_validate(row[0]) if row else None

    def list_gateways(self) -> list[GatewayConnection]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT payload FROM gateway_connections ORDER BY gateway_id"
            )
            rows = cursor.fetchall()
        return [GatewayConnection.model_validate(row[0]) for row in rows]

    @staticmethod
    def _insert_audit(
        cursor: psycopg.Cursor,
        action: str,
        actor_id: str | None,
        target_id: str | None,
        details: dict[str, object],
    ) -> None:
        cursor.execute(
            """
            INSERT INTO audit_records (action, actor_id, target_id, details)
            VALUES (%s, %s, %s, %s)
            """,
            (action, actor_id, target_id, Jsonb(details)),
        )

    def write_audit(
        self,
        action: str,
        actor_id: str | None,
        target_id: str | None,
        details: dict[str, object],
    ) -> None:
        with self._connect() as connection, connection.cursor() as cursor:
            self._insert_audit(cursor, action, actor_id, target_id, details)

    def list_audit(self, limit: int = 100) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT audit_id, occurred_at, actor_id, action, target_id, details
                FROM audit_records
                ORDER BY audit_id DESC
                LIMIT %s
                """,
                (limit,),
            )
            rows = cursor.fetchall()
        return [
            {
                "audit_id": row[0],
                "occurred_at": row[1].isoformat(),
                "actor_id": row[2],
                "action": row[3],
                "target_id": row[4],
                "details": row[5],
            }
            for row in rows
        ]
