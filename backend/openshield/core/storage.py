import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime

import psycopg
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool, PoolTimeout

from openshield.core.audit_integrity import GENESIS_AUDIT_HASH
from openshield.core.storage_audit import PostgresAuditStoreMixin, StorageConfigurationError
from openshield.core.storage_events import PostgresEventStoreMixin
from openshield.core.storage_execution import PostgresExecutionStoreMixin
from openshield.core.storage_gateway_inventory import PostgresGatewayInventoryStoreMixin
from openshield.core.storage_incidents import PostgresIncidentStoreMixin
from openshield.core.storage_integrations import PostgresIntegrationStoreMixin
from openshield.core.storage_policies import PostgresPolicyStoreMixin
from openshield.gateway.models import GatewayConnection


class AdvisoryLockUnavailable(RuntimeError):
    """Another OpenShield Node process already owns the database process lock."""


class PostgresStore(
    PostgresAuditStoreMixin,
    PostgresEventStoreMixin,
    PostgresExecutionStoreMixin,
    PostgresGatewayInventoryStoreMixin,
    PostgresIncidentStoreMixin,
    PostgresIntegrationStoreMixin,
    PostgresPolicyStoreMixin,
):
    """Small synchronous PostgreSQL store for P0 state and event persistence."""

    def __init__(
        self,
        dsn: str,
        *,
        pool_min_size: int = 1,
        pool_max_size: int = 10,
        pool_timeout: float = 5.0,
    ) -> None:
        if not 1 <= pool_min_size <= pool_max_size <= 32:
            raise StorageConfigurationError(
                "Database pool sizes must satisfy 1 <= min_size <= max_size <= 32"
            )
        if not 0.05 <= pool_timeout <= 30:
            raise StorageConfigurationError(
                "Database pool timeout must be between 0.05 and 30 seconds"
            )
        self._dsn = dsn.strip()
        self._pool_min_size = pool_min_size
        self._pool_max_size = pool_max_size
        self._pool_timeout = pool_timeout
        self._pool: ConnectionPool | None = None
        self._pool_lock = threading.Lock()
        self._schema_ready = False
        self._schema_lock = threading.Lock()

    def open(self) -> None:
        """Open the bounded connection pool; safe to call more than once."""
        if not self._dsn:
            raise StorageConfigurationError("OPENSHIELD_DATABASE_URL is required")
        self.ensure_schema()
        with self._pool_lock:
            if self._pool is not None and not self._pool.closed:
                return
            pool = ConnectionPool(
                conninfo=self._dsn,
                min_size=self._pool_min_size,
                max_size=self._pool_max_size,
                timeout=self._pool_timeout,
                kwargs={"connect_timeout": 5},
                open=False,
            )
            try:
                pool.open(wait=True, timeout=self._pool_timeout)
            except Exception:
                pool.close()
                raise
            self._pool = pool

    def close(self) -> None:
        """Close the pool and all its connections."""
        with self._pool_lock:
            pool = self._pool
            self._pool = None
            if pool is not None and not pool.closed:
                pool.close()

    @contextmanager
    def advisory_lock(self, lock_id: int) -> Iterator[None]:
        """Hold a PostgreSQL session advisory lock without consuming a pool slot."""
        if (
            isinstance(lock_id, bool)
            or not isinstance(lock_id, int)
            or not -(1 << 63) <= lock_id < (1 << 63)
        ):
            raise ValueError("Advisory lock ID must be a signed 64-bit integer")
        if not self._dsn:
            raise StorageConfigurationError("OPENSHIELD_DATABASE_URL is required")

        connection = psycopg.connect(self._dsn, connect_timeout=5)
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_try_advisory_lock(%s)", (lock_id,))
                row = cursor.fetchone()
            acquired = row is not None and row[0] is True
            connection.commit()
            if not acquired:
                raise AdvisoryLockUnavailable(
                    "Another OpenShield Node process already holds the PostgreSQL process lock"
                )

            try:
                yield
            finally:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_advisory_unlock(%s)", (lock_id,))
                    released = cursor.fetchone()
                connection.commit()
                if released is None or released[0] is not True:
                    raise RuntimeError("OpenShield PostgreSQL process lock was not released")
        finally:
            connection.close()

    def _connect(self):
        if not self._dsn:
            raise StorageConfigurationError("OPENSHIELD_DATABASE_URL is required")
        # Lazy opening keeps direct store use in tests and one-off tooling safe.
        self.open()
        with self._pool_lock:
            pool = self._pool
        if pool is None:
            raise StorageConfigurationError("Database connection pool is not available")
        return pool.connection(timeout=self._pool_timeout)


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
                CREATE TABLE IF NOT EXISTS integration_secrets (
                    integration_id TEXT PRIMARY KEY REFERENCES integrations(integration_id) ON DELETE CASCADE,
                    encrypted_value BYTEA NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
                CREATE TABLE IF NOT EXISTS threat_intel_cache (
                    provider TEXT NOT NULL,
                    indicator_type TEXT NOT NULL,
                    indicator_value TEXT NOT NULL,
                    result JSONB NOT NULL,
                    fetched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    expires_at TIMESTAMPTZ NOT NULL,
                    PRIMARY KEY (provider, indicator_type, indicator_value)
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    indicator_type TEXT NOT NULL,
                    indicator_value TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('open', 'acknowledged', 'closed', 'false_positive')),
                    risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
                    payload JSONB NOT NULL,
                    first_seen_at TIMESTAMPTZ NOT NULL,
                    last_seen_at TIMESTAMPTZ NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    UNIQUE (indicator_type, indicator_value)
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS incident_events (
                    incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
                    event_id TEXT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
                    PRIMARY KEY (incident_id, event_id)
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS incident_investigations (
                    investigation_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
                    provider_integration_id TEXT NOT NULL,
                    provider_kind TEXT NOT NULL,
                    model TEXT NOT NULL,
                    prompt_version TEXT NOT NULL,
                    context_scope JSONB NOT NULL,
                    result JSONB NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS policies (
                    policy_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    enabled BOOLEAN NOT NULL DEFAULT TRUE,
                    indicator_type TEXT NOT NULL CHECK (indicator_type IN ('ip', 'domain')),
                    indicator_value TEXT NOT NULL,
                    action TEXT NOT NULL CHECK (action IN ('block_ip', 'block_domain')),
                    integration_id TEXT NOT NULL REFERENCES integrations(integration_id),
                    min_risk_score INTEGER NOT NULL CHECK (min_risk_score BETWEEN 0 AND 100),
                    autonomy_level INTEGER NOT NULL CHECK (autonomy_level BETWEEN 0 AND 3),
                    ttl_seconds INTEGER NOT NULL CHECK (ttl_seconds BETWEEN 60 AND 86400),
                    require_approval BOOLEAN NOT NULL DEFAULT TRUE,
                    direction TEXT NOT NULL DEFAULT 'destination' CHECK (direction IN ('source', 'destination')),
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS policy_decisions (
                    decision_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
                    policy_id TEXT NOT NULL REFERENCES policies(policy_id),
                    status TEXT NOT NULL CHECK (status IN (
                        'observe_only', 'pending_approval', 'approved', 'rejected',
                        'blocked', 'executing', 'executed', 'failed'
                    )),
                    rationale JSONB NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS response_executions (
                    execution_id TEXT PRIMARY KEY,
                    decision_id TEXT NOT NULL REFERENCES policy_decisions(decision_id),
                    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
                    policy_id TEXT NOT NULL REFERENCES policies(policy_id),
                    integration_id TEXT NOT NULL REFERENCES integrations(integration_id),
                    action TEXT NOT NULL CHECK (action IN ('block_ip', 'block_domain')),
                    indicator_type TEXT NOT NULL,
                    indicator_value TEXT NOT NULL,
                    direction TEXT NOT NULL DEFAULT 'destination',
                    status TEXT NOT NULL CHECK (status IN (
                        'pending_gateway', 'active', 'rollback_pending',
                        'rolled_back', 'rollback_failed', 'failed'
                    )),
                    ttl_seconds INTEGER NOT NULL,
                    expires_at TIMESTAMPTZ,
                    adapter_result JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    rolled_back_at TIMESTAMPTZ
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS gateway_commands (
                    command_id TEXT PRIMARY KEY,
                    gateway_id TEXT NOT NULL REFERENCES integrations(integration_id),
                    execution_id TEXT NOT NULL REFERENCES response_executions(execution_id) ON DELETE CASCADE,
                    action TEXT NOT NULL CHECK (action IN ('block_ip', 'unblock_ip')),
                    payload JSONB NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('pending', 'completed', 'failed')),
                    result JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS runtime_controls (
                    control_key TEXT PRIMARY KEY,
                    value JSONB NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS integration_poll_cursors (
                    integration_id TEXT PRIMARY KEY REFERENCES integrations(integration_id) ON DELETE CASCADE,
                    provider_kind TEXT NOT NULL,
                    cursor JSONB NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
                CREATE TABLE IF NOT EXISTS privacy_classification_overrides (
                    domain TEXT PRIMARY KEY,
                    action TEXT NOT NULL CHECK (action IN ('allow', 'tracker')),
                    reason TEXT NOT NULL DEFAULT '',
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
                CREATE TABLE IF NOT EXISTS gateway_discovery_snapshots (
                    gateway_id TEXT PRIMARY KEY,
                    payload JSONB NOT NULL,
                    observed_at TIMESTAMPTZ NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS network_devices (
                    gateway_id TEXT NOT NULL,
                    mac_address TEXT NOT NULL,
                    payload JSONB NOT NULL,
                    first_seen_at TIMESTAMPTZ NOT NULL,
                    last_seen_at TIMESTAMPTZ NOT NULL,
                    PRIMARY KEY (gateway_id, mac_address)
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS network_device_address_observations (
                    gateway_id TEXT NOT NULL,
                    mac_address TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    source TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    first_seen_at TIMESTAMPTZ NOT NULL,
                    last_seen_at TIMESTAMPTZ NOT NULL,
                    PRIMARY KEY (gateway_id, mac_address, ip_address, source)
                )
                """,
                """
                CREATE INDEX IF NOT EXISTS network_device_address_ip_idx
                ON network_device_address_observations (ip_address, last_seen_at DESC)
                """,
                """
                CREATE INDEX IF NOT EXISTS network_devices_last_seen_idx
                ON network_devices (last_seen_at DESC)
                """,
                """
                CREATE TABLE IF NOT EXISTS threat_indicators (
                    source_integration_id TEXT NOT NULL REFERENCES integrations(integration_id) ON DELETE CASCADE,
                    indicator_id TEXT NOT NULL,
                    indicator_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    category TEXT NOT NULL DEFAULT '',
                    event_id TEXT NOT NULL DEFAULT '',
                    comment TEXT NOT NULL DEFAULT '',
                    to_ids BOOLEAN NOT NULL DEFAULT TRUE,
                    source_timestamp TEXT NOT NULL DEFAULT '',
                    synced_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    PRIMARY KEY (source_integration_id, indicator_id)
                )
                """,
                """
                CREATE INDEX IF NOT EXISTS threat_indicators_value_idx
                ON threat_indicators (indicator_type, lower(value))
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
            event_timestamp_migration = (
                """
                ALTER TABLE events
                ADD COLUMN IF NOT EXISTS occurred_at TIMESTAMPTZ
                """,
                """
                UPDATE events
                SET occurred_at = CASE
                    WHEN pg_input_is_valid(
                        payload->>'occurred_at', 'timestamp with time zone'
                    )
                    THEN (payload->>'occurred_at')::timestamptz
                    ELSE received_at
                END
                WHERE occurred_at IS NULL
                """,
                "ALTER TABLE events ALTER COLUMN occurred_at SET DEFAULT NOW()",
                "ALTER TABLE events ALTER COLUMN occurred_at SET NOT NULL",
                "DROP INDEX IF EXISTS events_event_type_idx",
                """
                CREATE INDEX IF NOT EXISTS events_event_type_occurred_at_idx
                ON events ((payload->>'event_type'), occurred_at DESC)
                """,
            )
            threat_intel_cache_migration = (
                """
                CREATE INDEX IF NOT EXISTS threat_intel_cache_expires_at_idx
                ON threat_intel_cache (expires_at)
                """,
            )
            audit_chain_migration = (
                "ALTER TABLE audit_records ADD COLUMN IF NOT EXISTS previous_hash TEXT",
                "ALTER TABLE audit_records ADD COLUMN IF NOT EXISTS record_hash TEXT",
                """
                CREATE TABLE IF NOT EXISTS audit_chain_state (
                    chain_id SMALLINT PRIMARY KEY CHECK (chain_id = 1),
                    last_audit_id BIGINT NOT NULL DEFAULT 0 CHECK (last_audit_id >= 0),
                    last_hash TEXT NOT NULL
                        CHECK (
                            char_length(last_hash) = 64
                            AND last_hash ~ '^[0-9a-f]{64}'
                        )
                )
                """,
                """
                INSERT INTO audit_chain_state (chain_id, last_audit_id, last_hash)
                VALUES (1, 0, %s)
                ON CONFLICT (chain_id) DO NOTHING
                """,
            )
            audit_chain_finalize = (
                "ALTER TABLE audit_records ALTER COLUMN previous_hash SET NOT NULL",
                "ALTER TABLE audit_records ALTER COLUMN record_hash SET NOT NULL",
                """
                ALTER TABLE audit_records
                ADD CONSTRAINT audit_records_previous_hash_check
                CHECK (
                    char_length(previous_hash) = 64
                    AND previous_hash ~ '^[0-9a-f]{64}'
                )
                """,
                """
                ALTER TABLE audit_records
                ADD CONSTRAINT audit_records_record_hash_check
                CHECK (
                    char_length(record_hash) = 64
                    AND record_hash ~ '^[0-9a-f]{64}'
                )
                """,
                """
                CREATE OR REPLACE FUNCTION openshield_check_audit_record_insert()
                RETURNS trigger
                LANGUAGE plpgsql
                AS '
                DECLARE
                    chain_head_id BIGINT;
                    chain_head_hash TEXT;
                BEGIN
                    SELECT last_audit_id, last_hash
                    INTO chain_head_id, chain_head_hash
                    FROM audit_chain_state
                    WHERE chain_id = 1
                    FOR UPDATE;
                    IF chain_head_id IS NULL
                       OR NEW.audit_id <= chain_head_id
                       OR NEW.previous_hash IS DISTINCT FROM chain_head_hash THEN
                        RAISE EXCEPTION ''audit record does not extend the current chain head'';
                    END IF;
                    RETURN NEW;
                END;
                '
                """,
                "DROP TRIGGER IF EXISTS audit_records_chain_insert ON audit_records",
                """
                CREATE TRIGGER audit_records_chain_insert
                BEFORE INSERT ON audit_records
                FOR EACH ROW
                EXECUTE FUNCTION openshield_check_audit_record_insert()
                """,
                "DROP TRIGGER IF EXISTS audit_records_advance_head ON audit_records",
                """
                CREATE OR REPLACE FUNCTION openshield_advance_audit_chain_head()
                RETURNS trigger
                LANGUAGE plpgsql
                AS '
                BEGIN
                    UPDATE audit_chain_state
                    SET last_audit_id = NEW.audit_id, last_hash = NEW.record_hash
                    WHERE chain_id = 1;
                    RETURN NEW;
                END;
                '
                """,
                """
                CREATE TRIGGER audit_records_advance_head
                AFTER INSERT ON audit_records
                FOR EACH ROW
                EXECUTE FUNCTION openshield_advance_audit_chain_head()
                """,
                """
                CREATE OR REPLACE FUNCTION openshield_guard_audit_record_mutation()
                RETURNS trigger
                LANGUAGE plpgsql
                AS '
                BEGIN
                    RAISE EXCEPTION ''audit_records are append-only'';
                END;
                '
                """,
                "DROP TRIGGER IF EXISTS audit_records_immutable_update_delete ON audit_records",
                """
                CREATE TRIGGER audit_records_immutable_update_delete
                BEFORE UPDATE OR DELETE ON audit_records
                FOR EACH ROW
                EXECUTE FUNCTION openshield_guard_audit_record_mutation()
                """,
                """
                CREATE OR REPLACE FUNCTION openshield_guard_audit_record_truncate()
                RETURNS trigger
                LANGUAGE plpgsql
                AS '
                BEGIN
                    RAISE EXCEPTION ''audit_records cannot be truncated'';
                END;
                '
                """,
                "DROP TRIGGER IF EXISTS audit_records_immutable_truncate ON audit_records",
                """
                CREATE TRIGGER audit_records_immutable_truncate
                BEFORE TRUNCATE ON audit_records
                FOR EACH STATEMENT
                EXECUTE FUNCTION openshield_guard_audit_record_truncate()
                """,
            )
            migrations = (
                (1, "initial schema", statements),
                (2, "typed event occurrence timestamps", event_timestamp_migration),
                (3, "threat intelligence cache expiry index", threat_intel_cache_migration),
                (4, "tamper-evident audit record chain", audit_chain_migration),
            )
            with (
                psycopg.connect(self._dsn, connect_timeout=5) as connection,
                connection.cursor() as cursor,
            ):
                # Serialize schema upgrades across Node processes. The transaction-scoped
                # lock is released automatically on commit or rollback.
                cursor.execute("SELECT pg_advisory_xact_lock(731946205)")
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS schema_migrations (
                        version INTEGER PRIMARY KEY,
                        name TEXT NOT NULL,
                        applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    )
                """)
                cursor.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations")
                row = cursor.fetchone()
                current_version = int(row[0]) if row else 0
                latest_version = migrations[-1][0] if migrations else 0
                if current_version > latest_version:
                    raise StorageConfigurationError(
                        f"Database schema version {current_version} is newer than "
                        f"this application supports ({latest_version})"
                    )
                for version, name, migration_statements in migrations:
                    if version <= current_version:
                        continue
                    for statement in migration_statements:
                        if version == 4 and "INSERT INTO audit_chain_state" in statement:
                            cursor.execute(statement, (GENESIS_AUDIT_HASH,))
                        else:
                            cursor.execute(statement)
                    if version == 4:
                        self._backfill_audit_chain(cursor)
                        for statement in audit_chain_finalize:
                            cursor.execute(statement)
                    cursor.execute(
                        "INSERT INTO schema_migrations (version, name) VALUES (%s, %s)",
                        (version, name),
                    )
            self._schema_ready = True

    def is_ready(self) -> bool:
        try:
            with self._connect() as connection, connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                return cursor.fetchone() == (1,)
        except (psycopg.Error, PoolTimeout, StorageConfigurationError):
            return False

    def reset(self) -> None:
        with self._connect() as connection, connection.cursor() as cursor:
            # Test-only operation: the database owner temporarily disables triggers.
            cursor.execute("ALTER TABLE audit_records DISABLE TRIGGER USER")
            cursor.execute(
                "TRUNCATE TABLE integrations, integration_secrets, events, threat_intel_cache, "
                "incidents, incident_events, incident_investigations, policies, policy_decisions, "
                "response_executions, gateway_commands, runtime_controls, integration_poll_cursors, "
                "privacy_lists, privacy_classification_overrides, gateway_connections, "
                "gateway_discovery_snapshots, network_devices, network_device_address_observations, "
                "threat_indicators, audit_records, audit_chain_state RESTART IDENTITY CASCADE"
            )
            cursor.execute("ALTER TABLE audit_records ENABLE TRIGGER USER")
            cursor.execute(
                """
                INSERT INTO audit_chain_state (chain_id, last_audit_id, last_hash)
                VALUES (1, 0, %s)
                """,
                (GENESIS_AUDIT_HASH,),
            )

    def get_threat_intel_cache(
        self, provider: str, indicator_type: str, indicator_value: str
    ) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT result FROM threat_intel_cache
                WHERE provider = %s AND indicator_type = %s
                  AND indicator_value = %s AND expires_at > NOW()
                """,
                (provider, indicator_type, indicator_value),
            )
            row = cursor.fetchone()
        return row[0] if row else None

    def set_threat_intel_cache(
        self, provider: str, indicator_type: str, indicator_value: str,
        result: dict[str, object], ttl_seconds: int = 21600,
    ) -> None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO threat_intel_cache
                    (provider, indicator_type, indicator_value, result, expires_at)
                VALUES (%s, %s, %s, %s, NOW() + (%s * INTERVAL '1 second'))
                ON CONFLICT (provider, indicator_type, indicator_value) DO UPDATE
                SET result = EXCLUDED.result, fetched_at = NOW(), expires_at = EXCLUDED.expires_at
                """,
                (provider, indicator_type, indicator_value, Jsonb(result), ttl_seconds),
            )

    def expire_threat_intel_cache(self, limit: int = 500) -> int:
        if not 1 <= limit <= 10000:
            raise ValueError("Threat intelligence cache cleanup limit must be between 1 and 10000")
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                WITH expired AS (
                    SELECT provider, indicator_type, indicator_value
                    FROM threat_intel_cache
                    WHERE expires_at <= NOW()
                    ORDER BY expires_at
                    LIMIT %s
                    FOR UPDATE SKIP LOCKED
                )
                DELETE FROM threat_intel_cache AS cache
                USING expired
                WHERE cache.provider = expired.provider
                  AND cache.indicator_type = expired.indicator_type
                  AND cache.indicator_value = expired.indicator_value
                RETURNING 1
                """,
                (limit,),
            )
            return cursor.rowcount

    def list_inventory_observations(self, limit: int = 2000) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                WITH observations AS (
                    SELECT
                        COALESCE(payload #>> '{payload,src_ip}', payload #>> '{payload,id.orig_h}') AS address,
                        occurred_at,
                        COALESCE(payload #>> '{payload,proto}', payload #>> '{payload,app_proto}', 'unknown') AS protocol
                    FROM events
                    UNION ALL
                    SELECT
                        COALESCE(payload #>> '{payload,dest_ip}', payload #>> '{payload,id.resp_h}') AS address,
                        occurred_at,
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
                        COALESCE(
                            payload #>> '{payload,src_ip}',
                            payload #>> '{payload,id.orig_h}'
                        ) AS source,
                        COALESCE(
                            payload #>> '{payload,dest_ip}',
                            payload #>> '{payload,id.resp_h}'
                        ) AS target,
                        COALESCE(
                            payload #>> '{payload,proto}',
                            payload #>> '{payload,app_proto}',
                            'unknown'
                        ) AS protocol,
                        payload #>> '{source,integration_id}' AS integration_id,
                        payload->>'event_type' AS event_type,
                        occurred_at
                    FROM events
                )
                SELECT source, target, protocol, COUNT(*),
                       ARRAY_AGG(DISTINCT integration_id),
                       ARRAY_AGG(DISTINCT event_type),
                       MIN(occurred_at), MAX(occurred_at)
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
            {
                "source": row[0],
                "target": row[1],
                "protocol": row[2],
                "observations": row[3],
                "source_integration_ids": row[4],
                "source_event_types": row[5],
                "first_seen": row[6],
                "last_seen": row[7],
            }
            for row in rows
        ]

    def list_nat_observations(self, limit: int = 1000) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                WITH translations AS (
                    SELECT
                        COALESCE(
                            payload #>> '{payload,src_ip}',
                            payload #>> '{payload,id.orig_h}'
                        ) AS original,
                        COALESCE(
                            payload #>> '{payload,translated_src_ip}',
                            payload #>> '{payload,nat_src_ip}'
                        ) AS translated,
                        COALESCE(payload #>> '{payload,proto}', 'unknown') AS protocol,
                        payload #>> '{source,integration_id}' AS integration_id,
                        payload->>'event_type' AS event_type,
                        occurred_at
                    FROM events
                    UNION ALL
                    SELECT
                        COALESCE(
                            payload #>> '{payload,dest_ip}',
                            payload #>> '{payload,id.resp_h}'
                        ) AS original,
                        COALESCE(
                            payload #>> '{payload,translated_dest_ip}',
                            payload #>> '{payload,nat_dest_ip}'
                        ) AS translated,
                        COALESCE(payload #>> '{payload,proto}', 'unknown') AS protocol,
                        payload #>> '{source,integration_id}' AS integration_id,
                        payload->>'event_type' AS event_type,
                        occurred_at
                    FROM events
                )
                SELECT original, translated, protocol, COUNT(*),
                       ARRAY_AGG(DISTINCT integration_id),
                       ARRAY_AGG(DISTINCT event_type),
                       MIN(occurred_at), MAX(occurred_at)
                FROM translations
                WHERE original IS NOT NULL AND translated IS NOT NULL
                  AND original <> translated
                GROUP BY original, translated, protocol
                ORDER BY COUNT(*) DESC, original, translated
                LIMIT %s
                """,
                (limit,),
            )
            rows = cursor.fetchall()
        return [
            {
                "source": row[0],
                "target": row[1],
                "protocol": row[2],
                "observations": row[3],
                "source_integration_ids": row[4],
                "source_event_types": row[5],
                "first_seen": row[6],
                "last_seen": row[7],
            }
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

    def privacy_source_stats(self) -> dict[str, dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT payload #>> '{source,integration_id}', COUNT(*),
                       MAX((payload->>'observed_at')::timestamptz)
                FROM events
                WHERE payload->>'event_type' = 'privacy.dns.query'
                GROUP BY payload #>> '{source,integration_id}'
                """
            )
            rows = cursor.fetchall()
        return {
            row[0]: {"queries_seen": row[1], "last_observed_at": row[2]}
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
                  AND occurred_at >= NOW() - (%s * INTERVAL '1 day')
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
                  AND occurred_at >= NOW() - (%s * INTERVAL '1 day')
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
                SELECT date_trunc('day', occurred_at)::date,
                       COUNT(*),
                       COUNT(*) FILTER (WHERE payload #>> '{payload,status}' = 'blocked'),
                       COUNT(*) FILTER (WHERE payload #>> '{payload,category}' = 'tracker'),
                       COUNT(DISTINCT payload #>> '{payload,domain}')
                FROM events
                WHERE payload->>'event_type' = 'privacy.dns.query'
                  AND occurred_at >= NOW() - (%s * INTERVAL '1 day')
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

    def list_privacy_classification_overrides(self) -> dict[str, dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT domain, action, reason, updated_at FROM privacy_classification_overrides ORDER BY domain"
            )
            rows = cursor.fetchall()
        return {
            row[0]: {"action": row[1], "reason": row[2], "updated_at": row[3].isoformat()}
            for row in rows
        }

    def upsert_privacy_classification_override(
        self, domain: str, action: str, reason: str = ""
    ) -> None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO privacy_classification_overrides (domain, action, reason)
                VALUES (%s, %s, %s)
                ON CONFLICT (domain) DO UPDATE
                SET action = EXCLUDED.action, reason = EXCLUDED.reason, updated_at = NOW()
                RETURNING updated_at
                """,
                (domain, action, reason),
            )
            updated_at = cursor.fetchone()[0]
            self._insert_audit(
                cursor, "privacy.classification_override.updated", None, domain,
                {"action": action, "reason": reason, "updated_at": updated_at.isoformat()},
            )

    def delete_privacy_classification_override(self, domain: str) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM privacy_classification_overrides WHERE domain = %s RETURNING domain",
                (domain,),
            )
            deleted = cursor.fetchone() is not None
            if deleted:
                self._insert_audit(cursor, "privacy.classification_override.deleted", None, domain, {})
            return deleted

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

    def delete_privacy_list_item(
        self, integration_id: str, list_type: str, domain: str,
        expected_comment: str | None = None,
    ) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                DELETE FROM privacy_lists
                WHERE integration_id = %s AND list_type = %s AND domain = %s
                  AND (%s::text IS NULL OR comment = %s)
                RETURNING domain
                """,
                (integration_id, list_type, domain, expected_comment, expected_comment),
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


    def upsert_threat_indicators(
        self, integration_id: str, indicators: list[dict[str, object]]
    ) -> int:
        return self.sync_threat_indicators(integration_id, indicators)["stored"]

    def sync_threat_indicators(
        self,
        integration_id: str,
        indicators: list[dict[str, object]],
        *,
        complete_snapshot: bool = False,
    ) -> dict[str, int]:
        rows = [
            (
                integration_id,
                str(item["indicator_id"]),
                str(item["indicator_type"]),
                str(item["value"]),
                str(item.get("category") or ""),
                str(item.get("event_id") or ""),
                str(item.get("comment") or ""),
                bool(item.get("to_ids", True)),
                str(item.get("source_timestamp") or ""),
            )
            for item in indicators
        ]
        indicator_ids = [row[1] for row in rows]
        with self._connect() as connection, connection.cursor() as cursor:
            if rows:
                cursor.executemany(
                    """
                    INSERT INTO threat_indicators (
                        source_integration_id, indicator_id, indicator_type, value,
                        category, event_id, comment, to_ids, source_timestamp
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (source_integration_id, indicator_id) DO UPDATE SET
                        indicator_type = EXCLUDED.indicator_type,
                        value = EXCLUDED.value,
                        category = EXCLUDED.category,
                        event_id = EXCLUDED.event_id,
                        comment = EXCLUDED.comment,
                        to_ids = EXCLUDED.to_ids,
                        source_timestamp = EXCLUDED.source_timestamp,
                        synced_at = NOW()
                    """,
                    rows,
                )
            removed = 0
            if complete_snapshot:
                cursor.execute(
                    """
                    DELETE FROM threat_indicators
                    WHERE source_integration_id = %s
                      AND NOT (indicator_id = ANY(%s))
                    """,
                    (integration_id, indicator_ids),
                )
                removed = cursor.rowcount
            self._insert_audit(
                cursor, "threat.indicators.synced", None, integration_id,
                {
                    "received": len(rows),
                    "removed": removed,
                    "provider": "misp",
                    "reconciled": complete_snapshot,
                },
            )
        return {"stored": len(rows), "removed": removed}

    def list_threat_indicators(
        self, integration_id: str | None = None, limit: int = 200
    ) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            if integration_id:
                cursor.execute(
                    """
                    SELECT source_integration_id, indicator_id, indicator_type, value,
                           category, event_id, comment, to_ids, source_timestamp, synced_at
                    FROM threat_indicators
                    WHERE source_integration_id = %s
                    ORDER BY synced_at DESC, indicator_type, value
                    LIMIT %s
                    """,
                    (integration_id, limit),
                )
            else:
                cursor.execute(
                    """
                    SELECT source_integration_id, indicator_id, indicator_type, value,
                           category, event_id, comment, to_ids, source_timestamp, synced_at
                    FROM threat_indicators
                    ORDER BY synced_at DESC, indicator_type, value
                    LIMIT %s
                    """,
                    (limit,),
                )
            rows = cursor.fetchall()
        return [
            {
                "integration_id": row[0],
                "indicator_id": row[1],
                "indicator_type": row[2],
                "value": row[3],
                "category": row[4],
                "event_id": row[5],
                "comment": row[6],
                "to_ids": row[7],
                "source_timestamp": row[8],
                "synced_at": row[9].isoformat(),
            }
            for row in rows
        ]
