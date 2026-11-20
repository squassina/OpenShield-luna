import ipaddress
import re
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime

import psycopg
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool, PoolTimeout

from openshield.core.audit_integrity import GENESIS_AUDIT_HASH, audit_record_hash
from openshield.events.models import EventEnvelope
from openshield.gateway.models import GatewayConnection
from openshield.integrations.models import Integration


def _has_valid_device_address(device: dict[str, object]) -> bool:
    candidates = [device.get("ip_address")]
    for field in ("ipv4_addresses", "ipv6_addresses"):
        values = device.get(field)
        if isinstance(values, list):
            candidates.extend(values)
    for value in candidates:
        if isinstance(value, str):
            try:
                ipaddress.ip_address(value)
                return True
            except ValueError:
                continue
    return False


class StorageConfigurationError(RuntimeError):
    pass


class AdvisoryLockUnavailable(RuntimeError):
    """Another OpenShield Node process already owns the database process lock."""


class PostgresStore:
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

    @staticmethod
    def _backfill_audit_chain(cursor: psycopg.Cursor) -> None:
        """Backfill legacy audit rows in bounded batches inside the migration transaction."""
        cursor.execute(
            """
            SELECT last_audit_id, last_hash
            FROM audit_chain_state
            WHERE chain_id = 1
            FOR UPDATE
            """
        )
        state = cursor.fetchone()
        if state is None or int(state[0]) != 0 or state[1] != GENESIS_AUDIT_HASH:
            raise StorageConfigurationError(
                "Audit chain state is not at its expected migration baseline"
            )

        last_audit_id = 0
        previous_hash = GENESIS_AUDIT_HASH
        while True:
            cursor.execute(
                """
                SELECT audit_id, occurred_at, actor_id, action, target_id, details,
                       previous_hash, record_hash
                FROM audit_records
                WHERE audit_id > %s
                ORDER BY audit_id
                LIMIT 500
                FOR UPDATE
                """,
                (last_audit_id,),
            )
            rows = cursor.fetchall()
            if not rows:
                break

            for row in rows:
                if row[6] is not None or row[7] is not None:
                    raise StorageConfigurationError(
                        "Legacy audit records contain unexpected chain hashes"
                    )
                audit_id = int(row[0])
                record_hash = audit_record_hash(
                    audit_id=audit_id,
                    occurred_at=row[1],
                    actor_id=row[2],
                    action=str(row[3]),
                    target_id=row[4],
                    details=row[5],
                    previous_hash=previous_hash,
                )
                cursor.execute(
                    """
                    UPDATE audit_records
                    SET previous_hash = %s, record_hash = %s
                    WHERE audit_id = %s
                    """,
                    (previous_hash, record_hash, audit_id),
                )
                last_audit_id = audit_id
                previous_hash = record_hash

        cursor.execute(
            """
            UPDATE audit_chain_state
            SET last_audit_id = %s, last_hash = %s
            WHERE chain_id = 1
            """,
            (last_audit_id, previous_hash),
        )

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
                        CHECK (last_hash ~ '^[0-9a-f]{64}            with (
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
                        if "%s" in statement and version == 4:
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
            cursor.execute("SELECT set_config('openshield.audit_reset', 'on', true)")
            cursor.execute(
                "TRUNCATE TABLE integrations, integration_secrets, events, threat_intel_cache, "
                "incidents, incident_events, incident_investigations, policies, policy_decisions, "
                "response_executions, gateway_commands, runtime_controls, integration_poll_cursors, "
                "privacy_lists, privacy_classification_overrides, gateway_connections, "
                "gateway_discovery_snapshots, network_devices, network_device_address_observations, "
                "threat_indicators, audit_records, audit_chain_state RESTART IDENTITY CASCADE"
            )
            cursor.execute(
                """
                INSERT INTO audit_chain_state (chain_id, last_audit_id, last_hash)
                VALUES (1, 0, %s)
                """,
                (GENESIS_AUDIT_HASH,),
            )

    def create_incident_investigation(
        self, investigation_id: str, incident_id: str, provider_integration_id: str,
        provider_kind: str, model: str, prompt_version: str,
        context_scope: dict[str, object], result: dict[str, object],
    ) -> dict[str, object]:
        created_at = datetime.now(UTC)
        payload = {
            "investigation_id": investigation_id,
            "incident_id": incident_id,
            "provider_integration_id": provider_integration_id,
            "provider_kind": provider_kind,
            "model": model,
            "prompt_version": prompt_version,
            "context_scope": context_scope,
            "result": result,
            "created_at": created_at.isoformat(),
        }
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO incident_investigations
                    (investigation_id, incident_id, provider_integration_id, provider_kind,
                     model, prompt_version, context_scope, result, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    investigation_id, incident_id, provider_integration_id, provider_kind,
                    model, prompt_version, Jsonb(context_scope), Jsonb(result), created_at,
                ),
            )
            self._insert_audit(
                cursor, "incident.investigation.created", None, incident_id,
                {
                    "investigation_id": investigation_id,
                    "provider_integration_id": provider_integration_id,
                    "provider_kind": provider_kind,
                    "model": model,
                    "prompt_version": prompt_version,
                    "context_scope": context_scope,
                },
            )
        return payload

    def create_policy(self, policy: dict[str, object]) -> dict[str, object]:
        created_at = datetime.now(UTC)
        payload = {**policy, "created_at": created_at.isoformat(), "updated_at": created_at.isoformat()}
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO policies
                    (policy_id, name, enabled, indicator_type, indicator_value, action,
                     integration_id, min_risk_score, autonomy_level, ttl_seconds,
                     require_approval, direction)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    policy["policy_id"], policy["name"], policy.get("enabled", True),
                    policy["indicator_type"], policy["indicator_value"], policy["action"],
                    policy["integration_id"], policy["min_risk_score"], policy["autonomy_level"],
                    policy["ttl_seconds"], policy.get("require_approval", True),
                    policy.get("direction", "destination"),
                ),
            )
            self._insert_audit(
                cursor, "policy.created", None, str(policy["policy_id"]),
                {"action": policy["action"], "integration_id": policy["integration_id"],
                 "autonomy_level": policy["autonomy_level"], "ttl_seconds": policy["ttl_seconds"]},
            )
        return payload

    def list_policies(self, enabled_only: bool = False) -> list[dict[str, object]]:
        where = "WHERE enabled = TRUE" if enabled_only else ""
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                f"SELECT policy_id, name, enabled, indicator_type, indicator_value, action, "
                f"integration_id, min_risk_score, autonomy_level, ttl_seconds, require_approval, "
                f"direction, created_at, updated_at FROM policies {where} ORDER BY name"
            )
            rows = cursor.fetchall()
        return [
            {
                "policy_id": row[0], "name": row[1], "enabled": row[2],
                "indicator_type": row[3], "indicator_value": row[4], "action": row[5],
                "integration_id": row[6], "min_risk_score": row[7], "autonomy_level": row[8],
                "ttl_seconds": row[9], "require_approval": row[10], "direction": row[11],
                "created_at": row[12].isoformat(), "updated_at": row[13].isoformat(),
            }
            for row in rows
        ]

    def get_policy(self, policy_id: str) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT policy_id, name, enabled, indicator_type, indicator_value, action,
                       integration_id, min_risk_score, autonomy_level, ttl_seconds,
                       require_approval, direction, created_at, updated_at
                FROM policies WHERE policy_id = %s
                """,
                (policy_id,),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return {
            "policy_id": row[0], "name": row[1], "enabled": row[2],
            "indicator_type": row[3], "indicator_value": row[4], "action": row[5],
            "integration_id": row[6], "min_risk_score": row[7], "autonomy_level": row[8],
            "ttl_seconds": row[9], "require_approval": row[10], "direction": row[11],
            "created_at": row[12].isoformat(), "updated_at": row[13].isoformat(),
        }

    def update_policy(self, policy_id: str, changes: dict[str, object]) -> dict[str, object] | None:
        allowed = {
            "name", "enabled", "min_risk_score", "autonomy_level", "ttl_seconds",
            "require_approval", "direction",
        }
        updates = {key: value for key, value in changes.items() if key in allowed}
        if not updates:
            return self.get_policy(policy_id)
        assignments = ", ".join(f"{key} = %s" for key in updates)
        values = list(updates.values())
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                f"UPDATE policies SET {assignments}, updated_at = NOW() WHERE policy_id = %s",
                (*values, policy_id),
            )
            if cursor.rowcount == 0:
                return None
            self._insert_audit(cursor, "policy.updated", None, policy_id, updates)
        return self.get_policy(policy_id)

    def create_policy_decision(
        self, decision_id: str, incident_id: str, policy_id: str,
        status: str, rationale: dict[str, object],
    ) -> dict[str, object]:
        now = datetime.now(UTC)
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO policy_decisions
                    (decision_id, incident_id, policy_id, status, rationale)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (decision_id, incident_id, policy_id, status, Jsonb(rationale)),
            )
            self._insert_audit(
                cursor, "policy.decision.created", None, decision_id,
                {"incident_id": incident_id, "policy_id": policy_id, "status": status},
            )
        return {
            "decision_id": decision_id, "incident_id": incident_id,
            "policy_id": policy_id, "status": status, "rationale": rationale,
            "created_at": now.isoformat(),
        }

    def list_policy_decisions(self, limit: int = 100) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT decision_id, incident_id, policy_id, status, rationale,
                       created_at, updated_at
                FROM policy_decisions ORDER BY created_at DESC LIMIT %s
                """,
                (limit,),
            )
            rows = cursor.fetchall()
        return [
            {
                "decision_id": row[0], "incident_id": row[1], "policy_id": row[2],
                "status": row[3], "rationale": row[4],
                "created_at": row[5].isoformat(), "updated_at": row[6].isoformat(),
            }
            for row in rows
        ]

    def get_policy_decision(self, decision_id: str) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT decision_id, incident_id, policy_id, status, rationale,
                       created_at, updated_at
                FROM policy_decisions WHERE decision_id = %s
                """,
                (decision_id,),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return {
            "decision_id": row[0], "incident_id": row[1], "policy_id": row[2],
            "status": row[3], "rationale": row[4],
            "created_at": row[5].isoformat(), "updated_at": row[6].isoformat(),
        }

    def update_policy_decision(
        self, decision_id: str, status: str, rationale: dict[str, object] | None = None
    ) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT rationale FROM policy_decisions WHERE decision_id = %s FOR UPDATE",
                (decision_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            payload = {**row[0], **(rationale or {}), "status": status}
            cursor.execute(
                """
                UPDATE policy_decisions SET status = %s, rationale = %s, updated_at = NOW()
                WHERE decision_id = %s
                """,
                (status, Jsonb(payload), decision_id),
            )
            self._insert_audit(
                cursor, "policy.decision.status.updated", None, decision_id,
                {"status": status, **(rationale or {})},
            )
        return self.get_policy_decision(decision_id)

    def create_response_execution(self, execution: dict[str, object]) -> dict[str, object]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO response_executions
                    (execution_id, decision_id, incident_id, policy_id, integration_id,
                     action, indicator_type, indicator_value, direction, status, ttl_seconds,
                     expires_at, adapter_result)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    execution["execution_id"], execution["decision_id"], execution["incident_id"],
                    execution["policy_id"], execution["integration_id"], execution["action"],
                    execution["indicator_type"], execution["indicator_value"], execution["direction"],
                    execution["status"], execution["ttl_seconds"], execution.get("expires_at"),
                    Jsonb(execution.get("adapter_result", {})),
                ),
            )
            self._insert_audit(
                cursor, "response.execution.created", None, str(execution["execution_id"]),
                {"action": execution["action"], "indicator_type": execution["indicator_type"],
                 "integration_id": execution["integration_id"], "status": execution["status"],
                 "ttl_seconds": execution["ttl_seconds"]},
            )
        return execution

    @staticmethod
    def _response_execution_from_row(row: tuple[object, ...]) -> dict[str, object]:
        return {
            "execution_id": row[0], "decision_id": row[1], "incident_id": row[2],
            "policy_id": row[3], "integration_id": row[4], "action": row[5],
            "indicator_type": row[6], "indicator_value": row[7], "direction": row[8],
            "status": row[9], "ttl_seconds": row[10],
            "expires_at": row[11].isoformat() if row[11] else None,
            "adapter_result": row[12], "created_at": row[13].isoformat(),
            "rolled_back_at": row[14].isoformat() if row[14] else None,
        }

    def get_response_execution(self, execution_id: str) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT execution_id, decision_id, incident_id, policy_id, integration_id,
                       action, indicator_type, indicator_value, direction, status, ttl_seconds,
                       expires_at, adapter_result, created_at, rolled_back_at
                FROM response_executions WHERE execution_id = %s
                """,
                (execution_id,),
            )
            row = cursor.fetchone()
        return self._response_execution_from_row(row) if row is not None else None

    def update_response_execution(
        self, execution_id: str, status: str,
        adapter_result: dict[str, object] | None = None,
        expires_at: datetime | None = None, rolled_back_at: datetime | None = None,
    ) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE response_executions SET status = %s,
                    adapter_result = COALESCE(%s, adapter_result),
                    expires_at = COALESCE(%s, expires_at),
                    rolled_back_at = COALESCE(%s, rolled_back_at)
                WHERE execution_id = %s
                """,
                (
                    status, Jsonb(adapter_result) if adapter_result is not None else None,
                    expires_at, rolled_back_at, execution_id,
                ),
            )
            if cursor.rowcount == 0:
                return None
            self._insert_audit(
                cursor, "response.execution.status.updated", None, execution_id,
                {"status": status, **(adapter_result or {})},
            )
        return self.get_response_execution(execution_id)

    def list_response_executions(self, limit: int = 100) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT execution_id, decision_id, incident_id, policy_id, integration_id,
                       action, indicator_type, indicator_value, direction, status, ttl_seconds,
                       expires_at, adapter_result, created_at, rolled_back_at
                FROM response_executions
                ORDER BY created_at DESC LIMIT %s
                """,
                (limit,),
            )
            rows = cursor.fetchall()
        return [self._response_execution_from_row(row) for row in rows]

    def get_due_response_executions(self) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT execution_id, decision_id, incident_id, policy_id, integration_id,
                       action, indicator_type, indicator_value, direction, status, ttl_seconds,
                       expires_at, adapter_result, created_at, rolled_back_at
                FROM response_executions
                WHERE status IN ('active', 'rollback_failed') AND expires_at IS NOT NULL AND expires_at <= NOW()
                ORDER BY expires_at ASC LIMIT 50
                """
            )
            rows = cursor.fetchall()
        return [self._response_execution_from_row(row) for row in rows]

    def has_active_response_execution(
        self, indicator_type: str, indicator_value: str,
        integration_id: str, exclude_execution_id: str | None = None,
    ) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT 1 FROM response_executions
                WHERE indicator_type = %s AND indicator_value = %s AND integration_id = %s
                  AND status IN ('pending_gateway', 'active', 'rollback_pending', 'rollback_failed')
                  AND (%s::text IS NULL OR execution_id <> %s)
                LIMIT 1
                """,
                (indicator_type, indicator_value, integration_id, exclude_execution_id, exclude_execution_id),
            )
            return cursor.fetchone() is not None

    def enqueue_gateway_command(
        self, command_id: str, gateway_id: str, execution_id: str,
        action: str, payload: dict[str, object],
    ) -> dict[str, object]:
        now = datetime.now(UTC)
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO gateway_commands
                    (command_id, gateway_id, execution_id, action, payload, status)
                VALUES (%s, %s, %s, %s, %s, 'pending')
                """,
                (command_id, gateway_id, execution_id, action, Jsonb(payload)),
            )
            self._insert_audit(
                cursor, "gateway.command.queued", None, command_id,
                {"gateway_id": gateway_id, "execution_id": execution_id, "action": action},
            )
        return {
            "command_id": command_id, "gateway_id": gateway_id, "execution_id": execution_id,
            "action": action, "payload": payload, "status": "pending", "created_at": now.isoformat(),
        }

    def list_pending_gateway_commands(self, gateway_id: str, limit: int = 10) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT command_id, execution_id, action, payload, created_at
                FROM gateway_commands
                WHERE gateway_id = %s AND status = 'pending'
                ORDER BY created_at ASC LIMIT %s
                """,
                (gateway_id, limit),
            )
            rows = cursor.fetchall()
        return [
            {
                "command_id": row[0], "execution_id": row[1],
                "action": row[2], "payload": row[3], "created_at": row[4].isoformat(),
            }
            for row in rows
        ]

    def has_pending_gateway_command(self, execution_id: str, action: str) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT 1 FROM gateway_commands
                WHERE execution_id = %s AND action = %s AND status = 'pending'
                LIMIT 1
                """,
                (execution_id, action),
            )
            return cursor.fetchone() is not None

    def get_gateway_command(self, command_id: str) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT command_id, gateway_id, execution_id, action, payload,
                       status, result, created_at
                FROM gateway_commands WHERE command_id = %s
                """,
                (command_id,),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return {
            "command_id": row[0], "gateway_id": row[1], "execution_id": row[2],
            "action": row[3], "payload": row[4], "status": row[5],
            "result": row[6], "created_at": row[7].isoformat(),
        }

    def complete_gateway_command(
        self, command_id: str, status: str, result: dict[str, object]
    ) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT status, result FROM gateway_commands WHERE command_id = %s FOR UPDATE",
                (command_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            if row[0] == "pending":
                cursor.execute(
                    """
                    UPDATE gateway_commands SET status = %s, result = %s, updated_at = NOW()
                    WHERE command_id = %s
                    """,
                    (status, Jsonb(result), command_id),
                )
                self._insert_audit(
                    cursor, "gateway.command.completed", None, command_id,
                    {"status": status, "result_status": result.get("status")},
                )
            elif row[0] != status or row[1] != result:
                return None
        return self.get_gateway_command(command_id)

    def get_emergency_stop(self) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT value FROM runtime_controls WHERE control_key = 'emergency_stop'"
            )
            row = cursor.fetchone()
        return bool(row[0].get("active", True)) if row else True

    def set_emergency_stop(self, active: bool, actor_id: str | None = None) -> None:
        value = {"active": active}
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO runtime_controls (control_key, value)
                VALUES ('emergency_stop', %s)
                ON CONFLICT (control_key) DO UPDATE
                SET value = EXCLUDED.value, updated_at = NOW()
                """,
                (Jsonb(value),),
            )
            self._insert_audit(
                cursor, "response.emergency_stop.updated", actor_id, "emergency_stop", value,
            )

    def list_incident_investigations(
        self, incident_id: str, limit: int = 10
    ) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT investigation_id, incident_id, provider_integration_id,
                       provider_kind, model, prompt_version, context_scope, result, created_at
                FROM incident_investigations
                WHERE incident_id = %s
                ORDER BY created_at DESC LIMIT %s
                """,
                (incident_id, limit),
            )
            rows = cursor.fetchall()
        return [
            {
                "investigation_id": row[0], "incident_id": row[1],
                "provider_integration_id": row[2], "provider_kind": row[3],
                "model": row[4], "prompt_version": row[5],
                "context_scope": row[6], "result": row[7],
                "created_at": row[8].isoformat(),
            }
            for row in rows
        ]

    def get_events_by_ids(self, event_ids: list[str]) -> list[EventEnvelope]:
        if not event_ids:
            return []
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT payload FROM events WHERE event_id = ANY(%s)",
                (event_ids,),
            )
            rows = cursor.fetchall()
        return [EventEnvelope.model_validate(row[0]) for row in rows]

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

    def upsert_incident(
        self, incident: dict[str, object], event_ids: list[str],
        first_seen_at: datetime, last_seen_at: datetime,
    ) -> dict[str, object]:
        indicator_type = str(incident["indicator_type"])
        indicator_value = str(incident["indicator_value"])
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s))",
                (f"{indicator_type}:{indicator_value}",),
            )
            cursor.execute(
                """
                SELECT incident_id, status, payload, first_seen_at, last_seen_at
                FROM incidents
                WHERE indicator_type = %s AND indicator_value = %s
                FOR UPDATE
                """,
                (indicator_type, indicator_value),
            )
            row = cursor.fetchone()
            if row:
                incident_id, status, existing, old_first, old_last = row
                merged_event_ids = sorted(set(existing.get("event_ids", [])) | set(event_ids))
                merged_sources = sorted(set(existing.get("sources", [])) | set(incident.get("sources", [])))
                merged_evidence = {**existing.get("intel_evidence", {}), **incident.get("intel_evidence", {})}
                merged_source_events = {
                    item["event_id"]: item
                    for item in [*existing.get("source_events", []), *incident.get("source_events", [])]
                    if isinstance(item, dict) and isinstance(item.get("event_id"), str)
                }
                payload = {
                    **existing, **incident, "incident_id": incident_id,
                    "status": status, "event_ids": merged_event_ids,
                    "sources": merged_sources, "intel_evidence": merged_evidence,
                    "source_events": list(merged_source_events.values()),
                    "created_at": existing.get("created_at", incident.get("created_at")),
                }
                old_score = int(existing.get("risk_score", 0))
                if old_score > int(incident["risk_score"]):
                    payload["risk_score"] = old_score
                    payload["risk_level"] = existing.get("risk_level", incident.get("risk_level"))
                    payload["risk_factors"] = existing.get("risk_factors", incident.get("risk_factors", []))
                if status == "closed" and set(event_ids) - set(existing.get("event_ids", [])):
                    status = "open"
                    payload["status"] = status
                first_seen = min(old_first, first_seen_at)
                last_seen = max(old_last, last_seen_at)
                cursor.execute(
                    """
                    UPDATE incidents SET status = %s, risk_score = %s, payload = %s,
                        first_seen_at = %s, last_seen_at = %s, updated_at = NOW()
                    WHERE incident_id = %s
                    """,
                    (status, int(payload["risk_score"]), Jsonb(payload), first_seen, last_seen, incident_id),
                )
                action = "incident.updated"
            else:
                incident_id = str(incident["incident_id"])
                status = str(incident.get("status", "open"))
                payload = {**incident, "incident_id": incident_id, "status": status,
                           "event_ids": sorted(set(event_ids))}
                first_seen, last_seen = first_seen_at, last_seen_at
                cursor.execute(
                    """
                    INSERT INTO incidents
                        (incident_id, indicator_type, indicator_value, status, risk_score,
                         payload, first_seen_at, last_seen_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (incident_id, indicator_type, indicator_value, status,
                     int(payload["risk_score"]), Jsonb(payload), first_seen, last_seen),
                )
                action = "incident.created"
            for event_id in event_ids:
                cursor.execute(
                    """
                    INSERT INTO incident_events (incident_id, event_id)
                    VALUES (%s, %s) ON CONFLICT DO NOTHING
                    """,
                    (incident_id, event_id),
                )
            self._insert_audit(
                cursor, action, None, incident_id,
                {"indicator_type": indicator_type, "indicator_value": indicator_value,
                 "risk_score": int(payload["risk_score"]), "event_count": len(payload["event_ids"])},
            )
        return payload

    def list_incidents(
        self, limit: int = 100, status: str | None = None
    ) -> list[dict[str, object]]:
        filters = "WHERE status = %s" if status else ""
        params = (status, limit) if status else (limit,)
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                f"SELECT payload FROM incidents {filters} "
                "ORDER BY risk_score DESC, last_seen_at DESC LIMIT %s",
                params,
            )
            rows = cursor.fetchall()
        return [row[0] for row in rows]

    def get_incident(self, incident_id: str) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT payload FROM incidents WHERE incident_id = %s", (incident_id,)
            )
            row = cursor.fetchone()
        return row[0] if row else None

    def get_incident_events(self, incident_id: str) -> list[EventEnvelope]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT e.payload FROM incident_events ie
                JOIN events e ON e.event_id = ie.event_id
                WHERE ie.incident_id = %s
                ORDER BY e.received_at ASC, e.event_id ASC
                """,
                (incident_id,),
            )
            rows = cursor.fetchall()
        return [EventEnvelope.model_validate(row[0]) for row in rows]

    def update_incident_status(
        self, incident_id: str, status: str, reason: str = ""
    ) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT payload FROM incidents WHERE incident_id = %s FOR UPDATE",
                (incident_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            payload = {**row[0], "status": status, "status_reason": reason}
            cursor.execute(
                """
                UPDATE incidents SET status = %s, payload = %s, updated_at = NOW()
                WHERE incident_id = %s
                """,
                (status, Jsonb(payload), incident_id),
            )
            self._insert_audit(
                cursor, "incident.status.updated", None, incident_id,
                {"status": status, "reason": reason[:200]},
            )
        return payload

    def set_integration_secret(self, integration_id: str, encrypted_value: bytes) -> None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO integration_secrets (integration_id, encrypted_value)
                VALUES (%s, %s)
                ON CONFLICT (integration_id) DO UPDATE
                SET encrypted_value = EXCLUDED.encrypted_value, updated_at = NOW()
                """,
                (integration_id, encrypted_value),
            )
            self._insert_audit(
                cursor, "integration.secret.updated", None, integration_id,
                {"encrypted": True},
            )

    def get_integration_secret(self, integration_id: str) -> bytes | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT encrypted_value FROM integration_secrets WHERE integration_id = %s",
                (integration_id,),
            )
            row = cursor.fetchone()
        return bytes(row[0]) if row else None

    def list_integration_secret_ids(self) -> list[str]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT integration_id FROM integration_secrets ORDER BY integration_id"
            )
            rows = cursor.fetchall()
        return [str(row[0]) for row in rows]

    def delete_integration_secret(self, integration_id: str) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM integration_secrets WHERE integration_id = %s RETURNING integration_id",
                (integration_id,),
            )
            deleted = cursor.fetchone() is not None
            if deleted:
                self._insert_audit(
                    cursor, "integration.secret.deleted", None, integration_id, {},
                )
            return deleted

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

    def update_integration(
        self, integration: Integration, actor_id: str | None = None
    ) -> Integration | None:
        payload = integration.model_dump(mode="json")
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE integrations SET payload = %s
                WHERE integration_id = %s
                RETURNING integration_id
                """,
                (Jsonb(payload), integration.integration_id),
            )
            if cursor.fetchone() is None:
                return None
            self._insert_audit(
                cursor, "integration.updated", actor_id, integration.integration_id,
                {"kind": integration.kind},
            )
        return integration

    def delete_integration(
        self, integration_id: str, actor_id: str | None = None
    ) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM integrations WHERE integration_id = %s RETURNING payload",
                (integration_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return False
            integration = Integration.model_validate(row[0])
            self._insert_audit(
                cursor, "integration.deleted", actor_id, integration_id,
                {"kind": integration.kind, "history_preserved": True},
            )
        return True

    def get_integration_poll_cursor(self, integration_id: str) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT cursor FROM integration_poll_cursors WHERE integration_id = %s",
                (integration_id,),
            )
            row = cursor.fetchone()
        return row[0] if row else None

    def delete_integration_poll_cursor(self, integration_id: str) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM integration_poll_cursors WHERE integration_id = %s RETURNING integration_id",
                (integration_id,),
            )
            return cursor.fetchone() is not None

    def set_integration_poll_cursor(
        self, integration_id: str, provider_kind: str, value: dict[str, object]
    ) -> None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO integration_poll_cursors (integration_id, provider_kind, cursor)
                VALUES (%s, %s, %s)
                ON CONFLICT (integration_id) DO UPDATE
                SET provider_kind = EXCLUDED.provider_kind,
                    cursor = EXCLUDED.cursor, updated_at = NOW()
                """,
                (integration_id, provider_kind, Jsonb(value)),
            )

    def checkpoint_integration_poll_page(
        self,
        integration_id: str,
        provider_kind: str,
        value: dict[str, object],
        completion_details: dict[str, object],
        rejection_details: dict[str, object] | None = None,
    ) -> None:
        """Atomically persist page diagnostics and advance its provider cursor."""
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO integration_poll_cursors (integration_id, provider_kind, cursor)
                VALUES (%s, %s, %s)
                ON CONFLICT (integration_id) DO UPDATE
                SET provider_kind = EXCLUDED.provider_kind,
                    cursor = EXCLUDED.cursor, updated_at = NOW()
                """,
                (integration_id, provider_kind, Jsonb(value)),
            )
            if rejection_details is not None:
                self._insert_audit(
                    cursor, "privacy.provider_poll.records_rejected", None,
                    integration_id, rejection_details,
                )
            self._insert_audit(
                cursor, "privacy.provider_poll.completed", None,
                integration_id, completion_details,
            )

    def insert_event(self, event: EventEnvelope, actor_id: str | None = None) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO events (event_id, payload, occurred_at)
                VALUES (%s, %s, %s)
                ON CONFLICT (event_id) DO NOTHING
                RETURNING event_id
                """,
                (
                    event.event_id,
                    Jsonb(event.model_dump(mode="json")),
                    event.occurred_at,
                ),
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

    def record_gateway_discovery(
        self, gateway_id: str, payload: dict[str, object], observed_at: datetime
    ) -> None:
        snapshot = {
            "board": payload.get("board", {}),
            "interfaces": payload.get("interfaces", []),
            "device_discovery": payload.get("device_discovery", {}),
        }
        devices = payload.get("devices", [])
        if not isinstance(devices, list):
            devices = []
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO gateway_discovery_snapshots (gateway_id, payload, observed_at)
                VALUES (%s, %s, %s)
                ON CONFLICT (gateway_id) DO UPDATE
                SET payload = CASE
                        WHEN EXCLUDED.observed_at >= gateway_discovery_snapshots.observed_at
                        THEN EXCLUDED.payload ELSE gateway_discovery_snapshots.payload END,
                    observed_at = GREATEST(
                        gateway_discovery_snapshots.observed_at, EXCLUDED.observed_at
                    )
                """,
                (gateway_id, Jsonb(snapshot), observed_at),
            )
            for device in devices:
                if not isinstance(device, dict):
                    continue
                mac = device.get("mac_address")
                if not isinstance(mac, str) or not re.fullmatch(
                    r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac
                ):
                    continue
                if not _has_valid_device_address(device):
                    continue
                normalized_mac = mac.lower()
                cursor.execute(
                    """
                    INSERT INTO network_devices (
                        gateway_id, mac_address, payload, first_seen_at, last_seen_at
                    ) VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (gateway_id, mac_address) DO UPDATE
                    SET payload = CASE
                            WHEN EXCLUDED.last_seen_at >= network_devices.last_seen_at
                            THEN EXCLUDED.payload ELSE network_devices.payload END,
                        last_seen_at = GREATEST(
                            network_devices.last_seen_at, EXCLUDED.last_seen_at
                        )
                    """,
                    (gateway_id, normalized_mac, Jsonb(device), observed_at, observed_at),
                )
                address_evidence = device.get("address_evidence")
                if not isinstance(address_evidence, dict):
                    address_evidence = {}
                    for field in ("ipv4_addresses", "ipv6_addresses"):
                        addresses = device.get(field, [])
                        if isinstance(addresses, list):
                            for address in addresses:
                                if isinstance(address, str):
                                    address_evidence.setdefault(address, []).append({
                                        "source": "luci_host_hints",
                                        "confidence": "medium",
                                    })
                for address, evidence_items in address_evidence.items():
                    if not isinstance(address, str) or not isinstance(evidence_items, list):
                        continue
                    try:
                        parsed_address = ipaddress.ip_address(address)
                    except ValueError:
                        continue
                    if (
                        parsed_address.is_unspecified
                        or parsed_address.is_multicast
                        or parsed_address.is_loopback
                    ):
                        continue
                    for evidence in evidence_items:
                        if not isinstance(evidence, dict):
                            continue
                        source = evidence.get("source")
                        confidence = evidence.get("confidence")
                        if source not in {"luci_host_hints", "dhcp_lease"}:
                            continue
                        expected_confidence = (
                            "high" if source == "dhcp_lease" else "medium"
                        )
                        if confidence != expected_confidence:
                            confidence = expected_confidence
                        cursor.execute(
                            """
                            INSERT INTO network_device_address_observations (
                                gateway_id, mac_address, ip_address, source, confidence,
                                first_seen_at, last_seen_at
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (gateway_id, mac_address, ip_address, source)
                            DO UPDATE SET
                                confidence = EXCLUDED.confidence,
                                last_seen_at = GREATEST(
                                    network_device_address_observations.last_seen_at,
                                    EXCLUDED.last_seen_at
                                )
                            """,
                            (
                                gateway_id, normalized_mac, str(parsed_address), source,
                                confidence, observed_at, observed_at,
                            ),
                        )

    def list_gateway_discovery_snapshots(self) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT gateway_id, payload, observed_at FROM gateway_discovery_snapshots "
                "ORDER BY observed_at DESC, gateway_id"
            )
            rows = cursor.fetchall()
        return [
            {"gateway_id": row[0], "payload": row[1], "observed_at": row[2]}
            for row in rows
        ]

    def list_gateway_devices(self, limit: int = 2000) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT gateway_id, mac_address, payload, first_seen_at, last_seen_at
                FROM network_devices
                ORDER BY last_seen_at DESC, gateway_id, mac_address
                LIMIT %s
                """,
                (limit,),
            )
            rows = cursor.fetchall()
        return [
            {
                "gateway_id": row[0], "mac_address": row[1], "payload": row[2],
                "first_seen_at": row[3], "last_seen_at": row[4],
            }
            for row in rows
        ]
    def list_device_identity_observations(
        self, limit: int = 10000
    ) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT gateway_id, mac_address, ip_address, source, confidence,
                       first_seen_at, last_seen_at
                FROM network_device_address_observations
                WHERE last_seen_at >= NOW() - INTERVAL '30 days'
                ORDER BY ip_address, last_seen_at DESC, gateway_id, mac_address, source
                LIMIT %s
                """,
                (limit,),
            )
            rows = cursor.fetchall()
        return [
            {
                "gateway_id": row[0],
                "mac_address": row[1],
                "ip_address": row[2],
                "source": row[3],
                "confidence": row[4],
                "first_seen_at": row[5],
                "last_seen_at": row[6],
            }
            for row in rows
        ]

    def list_events_page(self, integration_id=None, event_type=None, severity=None, limit=200, cursor=None):
        filters = []
        params = []
        if integration_id:
            filters.append("payload #>> '{source,integration_id}' = %s")
            params.append(integration_id)
        if event_type:
            filters.append("payload->>'event_type' = %s")
            params.append(event_type)
        if severity:
            filters.append("payload->>'severity' = %s")
            params.append(severity)
        if cursor:
            filters.append("(received_at, event_id) < (%s, %s)")
            params.extend(cursor)
        where = f"WHERE {' AND '.join(filters)}" if filters else ""
        params.append(limit + 1)
        with self._connect() as connection, connection.cursor() as db_cursor:
            db_cursor.execute(
                f"SELECT payload, received_at, event_id FROM events {where} "
                "ORDER BY received_at DESC, event_id DESC LIMIT %s", params
            )
            rows = db_cursor.fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        next_cursor = (rows[-1][1], rows[-1][2]) if has_more and rows else None
        return [EventEnvelope.model_validate(row[0]) for row in rows], next_cursor

    def purge_events_before(self, cutoff: datetime, batch_size: int = 1000) -> int:
        if not 1 <= batch_size <= 10000:
            raise ValueError("batch_size must be between 1 and 10000")
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """WITH doomed AS (
                    SELECT event_id FROM events WHERE received_at < %s
                    ORDER BY received_at, event_id LIMIT %s
                )
                DELETE FROM events e USING doomed d
                WHERE e.event_id = d.event_id RETURNING e.event_id""",
                (cutoff, batch_size),
            )
            return len(cursor.fetchall())

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
            SELECT last_audit_id, last_hash
            FROM audit_chain_state
            WHERE chain_id = 1
            FOR UPDATE
            """
        )
        head = cursor.fetchone()
        if head is None:
            raise StorageConfigurationError("Audit chain state is missing")
        last_audit_id, previous_hash = int(head[0]), str(head[1])

        cursor.execute(
            "SELECT nextval(pg_get_serial_sequence('audit_records', 'audit_id'))"
        )
        sequence_row = cursor.fetchone()
        if sequence_row is None:
            raise StorageConfigurationError("Audit record sequence is unavailable")
        audit_id = int(sequence_row[0])
        if audit_id <= last_audit_id:
            raise StorageConfigurationError("Audit record sequence is behind the chain head")

        occurred_at = datetime.now(UTC)
        record_hash = audit_record_hash(
            audit_id=audit_id,
            occurred_at=occurred_at,
            actor_id=actor_id,
            action=action,
            target_id=target_id,
            details=details,
            previous_hash=previous_hash,
        )
        cursor.execute(
            """
            INSERT INTO audit_records (
                audit_id, occurred_at, actor_id, action, target_id, details,
                previous_hash, record_hash
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                audit_id,
                occurred_at,
                actor_id,
                action,
                target_id,
                Jsonb(details),
                previous_hash,
                record_hash,
            ),
        )
        cursor.execute(
            """
            UPDATE audit_chain_state
            SET last_audit_id = %s, last_hash = %s
            WHERE chain_id = 1
            """,
            (audit_id, record_hash),
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
                SELECT audit_id, occurred_at, actor_id, action, target_id, details,
                       previous_hash, record_hash
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
                "previous_hash": row[6],
                "record_hash": row[7],
            }
            for row in rows
        ]

    def verify_audit_chain(self) -> dict[str, object]:
        """Verify record ordering, hashes, and the persisted chain head."""
        previous_hash = GENESIS_AUDIT_HASH
        last_audit_id = 0
        records_checked = 0
        error: str | None = None
        stored_head_id: int | None = None
        stored_head_hash: str | None = None

        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT audit_id, occurred_at, actor_id, action, target_id, details,
                       previous_hash, record_hash
                FROM audit_records
                ORDER BY audit_id
                """
            )
            while rows := cursor.fetchmany(500):
                for row in rows:
                    records_checked += 1
                    audit_id = int(row[0])
                    if row[6] != previous_hash:
                        error = "previous_hash_mismatch"
                        break
                    try:
                        calculated_hash = audit_record_hash(
                            audit_id=audit_id,
                            occurred_at=row[1],
                            actor_id=row[2],
                            action=str(row[3]),
                            target_id=row[4],
                            details=row[5],
                            previous_hash=previous_hash,
                        )
                    except (TypeError, ValueError):
                        error = "record_payload_invalid"
                        break
                    if row[7] != calculated_hash:
                        error = "record_hash_mismatch"
                        break
                    previous_hash = calculated_hash
                    last_audit_id = audit_id
                if error is not None:
                    break

            cursor.execute(
                """
                SELECT last_audit_id, last_hash
                FROM audit_chain_state
                WHERE chain_id = 1
                """
            )
            head = cursor.fetchone()
            if head is None:
                error = error or "chain_head_missing"
            else:
                stored_head_id = int(head[0])
                stored_head_hash = str(head[1])
                if (stored_head_id, stored_head_hash) != (last_audit_id, previous_hash):
                    error = error or "chain_head_mismatch"

        return {
            "valid": error is None,
            "records_checked": records_checked,
            "last_audit_id": last_audit_id,
            "computed_head_hash": previous_hash,
            "stored_head_audit_id": stored_head_id,
            "stored_head_hash": stored_head_hash,
            "error": error,
        }


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
                CHECK (previous_hash ~ '^[0-9a-f]{64}            with (
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
            cursor.execute("SELECT set_config('openshield.audit_reset', 'on', true)")
            cursor.execute(
                "TRUNCATE TABLE integrations, integration_secrets, events, threat_intel_cache, "
                "incidents, incident_events, incident_investigations, policies, policy_decisions, "
                "response_executions, gateway_commands, runtime_controls, integration_poll_cursors, "
                "privacy_lists, privacy_classification_overrides, gateway_connections, "
                "gateway_discovery_snapshots, network_devices, network_device_address_observations, "
                "threat_indicators, audit_records, audit_chain_state RESTART IDENTITY CASCADE"
            )
            cursor.execute(
                """
                INSERT INTO audit_chain_state (chain_id, last_audit_id, last_hash)
                VALUES (1, 0, %s)
                """,
                (GENESIS_AUDIT_HASH,),
            )

    def create_incident_investigation(
        self, investigation_id: str, incident_id: str, provider_integration_id: str,
        provider_kind: str, model: str, prompt_version: str,
        context_scope: dict[str, object], result: dict[str, object],
    ) -> dict[str, object]:
        created_at = datetime.now(UTC)
        payload = {
            "investigation_id": investigation_id,
            "incident_id": incident_id,
            "provider_integration_id": provider_integration_id,
            "provider_kind": provider_kind,
            "model": model,
            "prompt_version": prompt_version,
            "context_scope": context_scope,
            "result": result,
            "created_at": created_at.isoformat(),
        }
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO incident_investigations
                    (investigation_id, incident_id, provider_integration_id, provider_kind,
                     model, prompt_version, context_scope, result, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    investigation_id, incident_id, provider_integration_id, provider_kind,
                    model, prompt_version, Jsonb(context_scope), Jsonb(result), created_at,
                ),
            )
            self._insert_audit(
                cursor, "incident.investigation.created", None, incident_id,
                {
                    "investigation_id": investigation_id,
                    "provider_integration_id": provider_integration_id,
                    "provider_kind": provider_kind,
                    "model": model,
                    "prompt_version": prompt_version,
                    "context_scope": context_scope,
                },
            )
        return payload

    def create_policy(self, policy: dict[str, object]) -> dict[str, object]:
        created_at = datetime.now(UTC)
        payload = {**policy, "created_at": created_at.isoformat(), "updated_at": created_at.isoformat()}
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO policies
                    (policy_id, name, enabled, indicator_type, indicator_value, action,
                     integration_id, min_risk_score, autonomy_level, ttl_seconds,
                     require_approval, direction)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    policy["policy_id"], policy["name"], policy.get("enabled", True),
                    policy["indicator_type"], policy["indicator_value"], policy["action"],
                    policy["integration_id"], policy["min_risk_score"], policy["autonomy_level"],
                    policy["ttl_seconds"], policy.get("require_approval", True),
                    policy.get("direction", "destination"),
                ),
            )
            self._insert_audit(
                cursor, "policy.created", None, str(policy["policy_id"]),
                {"action": policy["action"], "integration_id": policy["integration_id"],
                 "autonomy_level": policy["autonomy_level"], "ttl_seconds": policy["ttl_seconds"]},
            )
        return payload

    def list_policies(self, enabled_only: bool = False) -> list[dict[str, object]]:
        where = "WHERE enabled = TRUE" if enabled_only else ""
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                f"SELECT policy_id, name, enabled, indicator_type, indicator_value, action, "
                f"integration_id, min_risk_score, autonomy_level, ttl_seconds, require_approval, "
                f"direction, created_at, updated_at FROM policies {where} ORDER BY name"
            )
            rows = cursor.fetchall()
        return [
            {
                "policy_id": row[0], "name": row[1], "enabled": row[2],
                "indicator_type": row[3], "indicator_value": row[4], "action": row[5],
                "integration_id": row[6], "min_risk_score": row[7], "autonomy_level": row[8],
                "ttl_seconds": row[9], "require_approval": row[10], "direction": row[11],
                "created_at": row[12].isoformat(), "updated_at": row[13].isoformat(),
            }
            for row in rows
        ]

    def get_policy(self, policy_id: str) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT policy_id, name, enabled, indicator_type, indicator_value, action,
                       integration_id, min_risk_score, autonomy_level, ttl_seconds,
                       require_approval, direction, created_at, updated_at
                FROM policies WHERE policy_id = %s
                """,
                (policy_id,),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return {
            "policy_id": row[0], "name": row[1], "enabled": row[2],
            "indicator_type": row[3], "indicator_value": row[4], "action": row[5],
            "integration_id": row[6], "min_risk_score": row[7], "autonomy_level": row[8],
            "ttl_seconds": row[9], "require_approval": row[10], "direction": row[11],
            "created_at": row[12].isoformat(), "updated_at": row[13].isoformat(),
        }

    def update_policy(self, policy_id: str, changes: dict[str, object]) -> dict[str, object] | None:
        allowed = {
            "name", "enabled", "min_risk_score", "autonomy_level", "ttl_seconds",
            "require_approval", "direction",
        }
        updates = {key: value for key, value in changes.items() if key in allowed}
        if not updates:
            return self.get_policy(policy_id)
        assignments = ", ".join(f"{key} = %s" for key in updates)
        values = list(updates.values())
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                f"UPDATE policies SET {assignments}, updated_at = NOW() WHERE policy_id = %s",
                (*values, policy_id),
            )
            if cursor.rowcount == 0:
                return None
            self._insert_audit(cursor, "policy.updated", None, policy_id, updates)
        return self.get_policy(policy_id)

    def create_policy_decision(
        self, decision_id: str, incident_id: str, policy_id: str,
        status: str, rationale: dict[str, object],
    ) -> dict[str, object]:
        now = datetime.now(UTC)
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO policy_decisions
                    (decision_id, incident_id, policy_id, status, rationale)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (decision_id, incident_id, policy_id, status, Jsonb(rationale)),
            )
            self._insert_audit(
                cursor, "policy.decision.created", None, decision_id,
                {"incident_id": incident_id, "policy_id": policy_id, "status": status},
            )
        return {
            "decision_id": decision_id, "incident_id": incident_id,
            "policy_id": policy_id, "status": status, "rationale": rationale,
            "created_at": now.isoformat(),
        }

    def list_policy_decisions(self, limit: int = 100) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT decision_id, incident_id, policy_id, status, rationale,
                       created_at, updated_at
                FROM policy_decisions ORDER BY created_at DESC LIMIT %s
                """,
                (limit,),
            )
            rows = cursor.fetchall()
        return [
            {
                "decision_id": row[0], "incident_id": row[1], "policy_id": row[2],
                "status": row[3], "rationale": row[4],
                "created_at": row[5].isoformat(), "updated_at": row[6].isoformat(),
            }
            for row in rows
        ]

    def get_policy_decision(self, decision_id: str) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT decision_id, incident_id, policy_id, status, rationale,
                       created_at, updated_at
                FROM policy_decisions WHERE decision_id = %s
                """,
                (decision_id,),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return {
            "decision_id": row[0], "incident_id": row[1], "policy_id": row[2],
            "status": row[3], "rationale": row[4],
            "created_at": row[5].isoformat(), "updated_at": row[6].isoformat(),
        }

    def update_policy_decision(
        self, decision_id: str, status: str, rationale: dict[str, object] | None = None
    ) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT rationale FROM policy_decisions WHERE decision_id = %s FOR UPDATE",
                (decision_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            payload = {**row[0], **(rationale or {}), "status": status}
            cursor.execute(
                """
                UPDATE policy_decisions SET status = %s, rationale = %s, updated_at = NOW()
                WHERE decision_id = %s
                """,
                (status, Jsonb(payload), decision_id),
            )
            self._insert_audit(
                cursor, "policy.decision.status.updated", None, decision_id,
                {"status": status, **(rationale or {})},
            )
        return self.get_policy_decision(decision_id)

    def create_response_execution(self, execution: dict[str, object]) -> dict[str, object]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO response_executions
                    (execution_id, decision_id, incident_id, policy_id, integration_id,
                     action, indicator_type, indicator_value, direction, status, ttl_seconds,
                     expires_at, adapter_result)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    execution["execution_id"], execution["decision_id"], execution["incident_id"],
                    execution["policy_id"], execution["integration_id"], execution["action"],
                    execution["indicator_type"], execution["indicator_value"], execution["direction"],
                    execution["status"], execution["ttl_seconds"], execution.get("expires_at"),
                    Jsonb(execution.get("adapter_result", {})),
                ),
            )
            self._insert_audit(
                cursor, "response.execution.created", None, str(execution["execution_id"]),
                {"action": execution["action"], "indicator_type": execution["indicator_type"],
                 "integration_id": execution["integration_id"], "status": execution["status"],
                 "ttl_seconds": execution["ttl_seconds"]},
            )
        return execution

    @staticmethod
    def _response_execution_from_row(row: tuple[object, ...]) -> dict[str, object]:
        return {
            "execution_id": row[0], "decision_id": row[1], "incident_id": row[2],
            "policy_id": row[3], "integration_id": row[4], "action": row[5],
            "indicator_type": row[6], "indicator_value": row[7], "direction": row[8],
            "status": row[9], "ttl_seconds": row[10],
            "expires_at": row[11].isoformat() if row[11] else None,
            "adapter_result": row[12], "created_at": row[13].isoformat(),
            "rolled_back_at": row[14].isoformat() if row[14] else None,
        }

    def get_response_execution(self, execution_id: str) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT execution_id, decision_id, incident_id, policy_id, integration_id,
                       action, indicator_type, indicator_value, direction, status, ttl_seconds,
                       expires_at, adapter_result, created_at, rolled_back_at
                FROM response_executions WHERE execution_id = %s
                """,
                (execution_id,),
            )
            row = cursor.fetchone()
        return self._response_execution_from_row(row) if row is not None else None

    def update_response_execution(
        self, execution_id: str, status: str,
        adapter_result: dict[str, object] | None = None,
        expires_at: datetime | None = None, rolled_back_at: datetime | None = None,
    ) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE response_executions SET status = %s,
                    adapter_result = COALESCE(%s, adapter_result),
                    expires_at = COALESCE(%s, expires_at),
                    rolled_back_at = COALESCE(%s, rolled_back_at)
                WHERE execution_id = %s
                """,
                (
                    status, Jsonb(adapter_result) if adapter_result is not None else None,
                    expires_at, rolled_back_at, execution_id,
                ),
            )
            if cursor.rowcount == 0:
                return None
            self._insert_audit(
                cursor, "response.execution.status.updated", None, execution_id,
                {"status": status, **(adapter_result or {})},
            )
        return self.get_response_execution(execution_id)

    def list_response_executions(self, limit: int = 100) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT execution_id, decision_id, incident_id, policy_id, integration_id,
                       action, indicator_type, indicator_value, direction, status, ttl_seconds,
                       expires_at, adapter_result, created_at, rolled_back_at
                FROM response_executions
                ORDER BY created_at DESC LIMIT %s
                """,
                (limit,),
            )
            rows = cursor.fetchall()
        return [self._response_execution_from_row(row) for row in rows]

    def get_due_response_executions(self) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT execution_id, decision_id, incident_id, policy_id, integration_id,
                       action, indicator_type, indicator_value, direction, status, ttl_seconds,
                       expires_at, adapter_result, created_at, rolled_back_at
                FROM response_executions
                WHERE status IN ('active', 'rollback_failed') AND expires_at IS NOT NULL AND expires_at <= NOW()
                ORDER BY expires_at ASC LIMIT 50
                """
            )
            rows = cursor.fetchall()
        return [self._response_execution_from_row(row) for row in rows]

    def has_active_response_execution(
        self, indicator_type: str, indicator_value: str,
        integration_id: str, exclude_execution_id: str | None = None,
    ) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT 1 FROM response_executions
                WHERE indicator_type = %s AND indicator_value = %s AND integration_id = %s
                  AND status IN ('pending_gateway', 'active', 'rollback_pending', 'rollback_failed')
                  AND (%s::text IS NULL OR execution_id <> %s)
                LIMIT 1
                """,
                (indicator_type, indicator_value, integration_id, exclude_execution_id, exclude_execution_id),
            )
            return cursor.fetchone() is not None

    def enqueue_gateway_command(
        self, command_id: str, gateway_id: str, execution_id: str,
        action: str, payload: dict[str, object],
    ) -> dict[str, object]:
        now = datetime.now(UTC)
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO gateway_commands
                    (command_id, gateway_id, execution_id, action, payload, status)
                VALUES (%s, %s, %s, %s, %s, 'pending')
                """,
                (command_id, gateway_id, execution_id, action, Jsonb(payload)),
            )
            self._insert_audit(
                cursor, "gateway.command.queued", None, command_id,
                {"gateway_id": gateway_id, "execution_id": execution_id, "action": action},
            )
        return {
            "command_id": command_id, "gateway_id": gateway_id, "execution_id": execution_id,
            "action": action, "payload": payload, "status": "pending", "created_at": now.isoformat(),
        }

    def list_pending_gateway_commands(self, gateway_id: str, limit: int = 10) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT command_id, execution_id, action, payload, created_at
                FROM gateway_commands
                WHERE gateway_id = %s AND status = 'pending'
                ORDER BY created_at ASC LIMIT %s
                """,
                (gateway_id, limit),
            )
            rows = cursor.fetchall()
        return [
            {
                "command_id": row[0], "execution_id": row[1],
                "action": row[2], "payload": row[3], "created_at": row[4].isoformat(),
            }
            for row in rows
        ]

    def has_pending_gateway_command(self, execution_id: str, action: str) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT 1 FROM gateway_commands
                WHERE execution_id = %s AND action = %s AND status = 'pending'
                LIMIT 1
                """,
                (execution_id, action),
            )
            return cursor.fetchone() is not None

    def get_gateway_command(self, command_id: str) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT command_id, gateway_id, execution_id, action, payload,
                       status, result, created_at
                FROM gateway_commands WHERE command_id = %s
                """,
                (command_id,),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return {
            "command_id": row[0], "gateway_id": row[1], "execution_id": row[2],
            "action": row[3], "payload": row[4], "status": row[5],
            "result": row[6], "created_at": row[7].isoformat(),
        }

    def complete_gateway_command(
        self, command_id: str, status: str, result: dict[str, object]
    ) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT status, result FROM gateway_commands WHERE command_id = %s FOR UPDATE",
                (command_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            if row[0] == "pending":
                cursor.execute(
                    """
                    UPDATE gateway_commands SET status = %s, result = %s, updated_at = NOW()
                    WHERE command_id = %s
                    """,
                    (status, Jsonb(result), command_id),
                )
                self._insert_audit(
                    cursor, "gateway.command.completed", None, command_id,
                    {"status": status, "result_status": result.get("status")},
                )
            elif row[0] != status or row[1] != result:
                return None
        return self.get_gateway_command(command_id)

    def get_emergency_stop(self) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT value FROM runtime_controls WHERE control_key = 'emergency_stop'"
            )
            row = cursor.fetchone()
        return bool(row[0].get("active", True)) if row else True

    def set_emergency_stop(self, active: bool, actor_id: str | None = None) -> None:
        value = {"active": active}
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO runtime_controls (control_key, value)
                VALUES ('emergency_stop', %s)
                ON CONFLICT (control_key) DO UPDATE
                SET value = EXCLUDED.value, updated_at = NOW()
                """,
                (Jsonb(value),),
            )
            self._insert_audit(
                cursor, "response.emergency_stop.updated", actor_id, "emergency_stop", value,
            )

    def list_incident_investigations(
        self, incident_id: str, limit: int = 10
    ) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT investigation_id, incident_id, provider_integration_id,
                       provider_kind, model, prompt_version, context_scope, result, created_at
                FROM incident_investigations
                WHERE incident_id = %s
                ORDER BY created_at DESC LIMIT %s
                """,
                (incident_id, limit),
            )
            rows = cursor.fetchall()
        return [
            {
                "investigation_id": row[0], "incident_id": row[1],
                "provider_integration_id": row[2], "provider_kind": row[3],
                "model": row[4], "prompt_version": row[5],
                "context_scope": row[6], "result": row[7],
                "created_at": row[8].isoformat(),
            }
            for row in rows
        ]

    def get_events_by_ids(self, event_ids: list[str]) -> list[EventEnvelope]:
        if not event_ids:
            return []
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT payload FROM events WHERE event_id = ANY(%s)",
                (event_ids,),
            )
            rows = cursor.fetchall()
        return [EventEnvelope.model_validate(row[0]) for row in rows]

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

    def upsert_incident(
        self, incident: dict[str, object], event_ids: list[str],
        first_seen_at: datetime, last_seen_at: datetime,
    ) -> dict[str, object]:
        indicator_type = str(incident["indicator_type"])
        indicator_value = str(incident["indicator_value"])
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s))",
                (f"{indicator_type}:{indicator_value}",),
            )
            cursor.execute(
                """
                SELECT incident_id, status, payload, first_seen_at, last_seen_at
                FROM incidents
                WHERE indicator_type = %s AND indicator_value = %s
                FOR UPDATE
                """,
                (indicator_type, indicator_value),
            )
            row = cursor.fetchone()
            if row:
                incident_id, status, existing, old_first, old_last = row
                merged_event_ids = sorted(set(existing.get("event_ids", [])) | set(event_ids))
                merged_sources = sorted(set(existing.get("sources", [])) | set(incident.get("sources", [])))
                merged_evidence = {**existing.get("intel_evidence", {}), **incident.get("intel_evidence", {})}
                merged_source_events = {
                    item["event_id"]: item
                    for item in [*existing.get("source_events", []), *incident.get("source_events", [])]
                    if isinstance(item, dict) and isinstance(item.get("event_id"), str)
                }
                payload = {
                    **existing, **incident, "incident_id": incident_id,
                    "status": status, "event_ids": merged_event_ids,
                    "sources": merged_sources, "intel_evidence": merged_evidence,
                    "source_events": list(merged_source_events.values()),
                    "created_at": existing.get("created_at", incident.get("created_at")),
                }
                old_score = int(existing.get("risk_score", 0))
                if old_score > int(incident["risk_score"]):
                    payload["risk_score"] = old_score
                    payload["risk_level"] = existing.get("risk_level", incident.get("risk_level"))
                    payload["risk_factors"] = existing.get("risk_factors", incident.get("risk_factors", []))
                if status == "closed" and set(event_ids) - set(existing.get("event_ids", [])):
                    status = "open"
                    payload["status"] = status
                first_seen = min(old_first, first_seen_at)
                last_seen = max(old_last, last_seen_at)
                cursor.execute(
                    """
                    UPDATE incidents SET status = %s, risk_score = %s, payload = %s,
                        first_seen_at = %s, last_seen_at = %s, updated_at = NOW()
                    WHERE incident_id = %s
                    """,
                    (status, int(payload["risk_score"]), Jsonb(payload), first_seen, last_seen, incident_id),
                )
                action = "incident.updated"
            else:
                incident_id = str(incident["incident_id"])
                status = str(incident.get("status", "open"))
                payload = {**incident, "incident_id": incident_id, "status": status,
                           "event_ids": sorted(set(event_ids))}
                first_seen, last_seen = first_seen_at, last_seen_at
                cursor.execute(
                    """
                    INSERT INTO incidents
                        (incident_id, indicator_type, indicator_value, status, risk_score,
                         payload, first_seen_at, last_seen_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (incident_id, indicator_type, indicator_value, status,
                     int(payload["risk_score"]), Jsonb(payload), first_seen, last_seen),
                )
                action = "incident.created"
            for event_id in event_ids:
                cursor.execute(
                    """
                    INSERT INTO incident_events (incident_id, event_id)
                    VALUES (%s, %s) ON CONFLICT DO NOTHING
                    """,
                    (incident_id, event_id),
                )
            self._insert_audit(
                cursor, action, None, incident_id,
                {"indicator_type": indicator_type, "indicator_value": indicator_value,
                 "risk_score": int(payload["risk_score"]), "event_count": len(payload["event_ids"])},
            )
        return payload

    def list_incidents(
        self, limit: int = 100, status: str | None = None
    ) -> list[dict[str, object]]:
        filters = "WHERE status = %s" if status else ""
        params = (status, limit) if status else (limit,)
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                f"SELECT payload FROM incidents {filters} "
                "ORDER BY risk_score DESC, last_seen_at DESC LIMIT %s",
                params,
            )
            rows = cursor.fetchall()
        return [row[0] for row in rows]

    def get_incident(self, incident_id: str) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT payload FROM incidents WHERE incident_id = %s", (incident_id,)
            )
            row = cursor.fetchone()
        return row[0] if row else None

    def get_incident_events(self, incident_id: str) -> list[EventEnvelope]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT e.payload FROM incident_events ie
                JOIN events e ON e.event_id = ie.event_id
                WHERE ie.incident_id = %s
                ORDER BY e.received_at ASC, e.event_id ASC
                """,
                (incident_id,),
            )
            rows = cursor.fetchall()
        return [EventEnvelope.model_validate(row[0]) for row in rows]

    def update_incident_status(
        self, incident_id: str, status: str, reason: str = ""
    ) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT payload FROM incidents WHERE incident_id = %s FOR UPDATE",
                (incident_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            payload = {**row[0], "status": status, "status_reason": reason}
            cursor.execute(
                """
                UPDATE incidents SET status = %s, payload = %s, updated_at = NOW()
                WHERE incident_id = %s
                """,
                (status, Jsonb(payload), incident_id),
            )
            self._insert_audit(
                cursor, "incident.status.updated", None, incident_id,
                {"status": status, "reason": reason[:200]},
            )
        return payload

    def set_integration_secret(self, integration_id: str, encrypted_value: bytes) -> None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO integration_secrets (integration_id, encrypted_value)
                VALUES (%s, %s)
                ON CONFLICT (integration_id) DO UPDATE
                SET encrypted_value = EXCLUDED.encrypted_value, updated_at = NOW()
                """,
                (integration_id, encrypted_value),
            )
            self._insert_audit(
                cursor, "integration.secret.updated", None, integration_id,
                {"encrypted": True},
            )

    def get_integration_secret(self, integration_id: str) -> bytes | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT encrypted_value FROM integration_secrets WHERE integration_id = %s",
                (integration_id,),
            )
            row = cursor.fetchone()
        return bytes(row[0]) if row else None

    def list_integration_secret_ids(self) -> list[str]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT integration_id FROM integration_secrets ORDER BY integration_id"
            )
            rows = cursor.fetchall()
        return [str(row[0]) for row in rows]

    def delete_integration_secret(self, integration_id: str) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM integration_secrets WHERE integration_id = %s RETURNING integration_id",
                (integration_id,),
            )
            deleted = cursor.fetchone() is not None
            if deleted:
                self._insert_audit(
                    cursor, "integration.secret.deleted", None, integration_id, {},
                )
            return deleted

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

    def update_integration(
        self, integration: Integration, actor_id: str | None = None
    ) -> Integration | None:
        payload = integration.model_dump(mode="json")
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE integrations SET payload = %s
                WHERE integration_id = %s
                RETURNING integration_id
                """,
                (Jsonb(payload), integration.integration_id),
            )
            if cursor.fetchone() is None:
                return None
            self._insert_audit(
                cursor, "integration.updated", actor_id, integration.integration_id,
                {"kind": integration.kind},
            )
        return integration

    def delete_integration(
        self, integration_id: str, actor_id: str | None = None
    ) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM integrations WHERE integration_id = %s RETURNING payload",
                (integration_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return False
            integration = Integration.model_validate(row[0])
            self._insert_audit(
                cursor, "integration.deleted", actor_id, integration_id,
                {"kind": integration.kind, "history_preserved": True},
            )
        return True

    def get_integration_poll_cursor(self, integration_id: str) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT cursor FROM integration_poll_cursors WHERE integration_id = %s",
                (integration_id,),
            )
            row = cursor.fetchone()
        return row[0] if row else None

    def delete_integration_poll_cursor(self, integration_id: str) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM integration_poll_cursors WHERE integration_id = %s RETURNING integration_id",
                (integration_id,),
            )
            return cursor.fetchone() is not None

    def set_integration_poll_cursor(
        self, integration_id: str, provider_kind: str, value: dict[str, object]
    ) -> None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO integration_poll_cursors (integration_id, provider_kind, cursor)
                VALUES (%s, %s, %s)
                ON CONFLICT (integration_id) DO UPDATE
                SET provider_kind = EXCLUDED.provider_kind,
                    cursor = EXCLUDED.cursor, updated_at = NOW()
                """,
                (integration_id, provider_kind, Jsonb(value)),
            )

    def checkpoint_integration_poll_page(
        self,
        integration_id: str,
        provider_kind: str,
        value: dict[str, object],
        completion_details: dict[str, object],
        rejection_details: dict[str, object] | None = None,
    ) -> None:
        """Atomically persist page diagnostics and advance its provider cursor."""
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO integration_poll_cursors (integration_id, provider_kind, cursor)
                VALUES (%s, %s, %s)
                ON CONFLICT (integration_id) DO UPDATE
                SET provider_kind = EXCLUDED.provider_kind,
                    cursor = EXCLUDED.cursor, updated_at = NOW()
                """,
                (integration_id, provider_kind, Jsonb(value)),
            )
            if rejection_details is not None:
                self._insert_audit(
                    cursor, "privacy.provider_poll.records_rejected", None,
                    integration_id, rejection_details,
                )
            self._insert_audit(
                cursor, "privacy.provider_poll.completed", None,
                integration_id, completion_details,
            )

    def insert_event(self, event: EventEnvelope, actor_id: str | None = None) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO events (event_id, payload, occurred_at)
                VALUES (%s, %s, %s)
                ON CONFLICT (event_id) DO NOTHING
                RETURNING event_id
                """,
                (
                    event.event_id,
                    Jsonb(event.model_dump(mode="json")),
                    event.occurred_at,
                ),
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

    def record_gateway_discovery(
        self, gateway_id: str, payload: dict[str, object], observed_at: datetime
    ) -> None:
        snapshot = {
            "board": payload.get("board", {}),
            "interfaces": payload.get("interfaces", []),
            "device_discovery": payload.get("device_discovery", {}),
        }
        devices = payload.get("devices", [])
        if not isinstance(devices, list):
            devices = []
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO gateway_discovery_snapshots (gateway_id, payload, observed_at)
                VALUES (%s, %s, %s)
                ON CONFLICT (gateway_id) DO UPDATE
                SET payload = CASE
                        WHEN EXCLUDED.observed_at >= gateway_discovery_snapshots.observed_at
                        THEN EXCLUDED.payload ELSE gateway_discovery_snapshots.payload END,
                    observed_at = GREATEST(
                        gateway_discovery_snapshots.observed_at, EXCLUDED.observed_at
                    )
                """,
                (gateway_id, Jsonb(snapshot), observed_at),
            )
            for device in devices:
                if not isinstance(device, dict):
                    continue
                mac = device.get("mac_address")
                if not isinstance(mac, str) or not re.fullmatch(
                    r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac
                ):
                    continue
                if not _has_valid_device_address(device):
                    continue
                normalized_mac = mac.lower()
                cursor.execute(
                    """
                    INSERT INTO network_devices (
                        gateway_id, mac_address, payload, first_seen_at, last_seen_at
                    ) VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (gateway_id, mac_address) DO UPDATE
                    SET payload = CASE
                            WHEN EXCLUDED.last_seen_at >= network_devices.last_seen_at
                            THEN EXCLUDED.payload ELSE network_devices.payload END,
                        last_seen_at = GREATEST(
                            network_devices.last_seen_at, EXCLUDED.last_seen_at
                        )
                    """,
                    (gateway_id, normalized_mac, Jsonb(device), observed_at, observed_at),
                )
                address_evidence = device.get("address_evidence")
                if not isinstance(address_evidence, dict):
                    address_evidence = {}
                    for field in ("ipv4_addresses", "ipv6_addresses"):
                        addresses = device.get(field, [])
                        if isinstance(addresses, list):
                            for address in addresses:
                                if isinstance(address, str):
                                    address_evidence.setdefault(address, []).append({
                                        "source": "luci_host_hints",
                                        "confidence": "medium",
                                    })
                for address, evidence_items in address_evidence.items():
                    if not isinstance(address, str) or not isinstance(evidence_items, list):
                        continue
                    try:
                        parsed_address = ipaddress.ip_address(address)
                    except ValueError:
                        continue
                    if (
                        parsed_address.is_unspecified
                        or parsed_address.is_multicast
                        or parsed_address.is_loopback
                    ):
                        continue
                    for evidence in evidence_items:
                        if not isinstance(evidence, dict):
                            continue
                        source = evidence.get("source")
                        confidence = evidence.get("confidence")
                        if source not in {"luci_host_hints", "dhcp_lease"}:
                            continue
                        expected_confidence = (
                            "high" if source == "dhcp_lease" else "medium"
                        )
                        if confidence != expected_confidence:
                            confidence = expected_confidence
                        cursor.execute(
                            """
                            INSERT INTO network_device_address_observations (
                                gateway_id, mac_address, ip_address, source, confidence,
                                first_seen_at, last_seen_at
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (gateway_id, mac_address, ip_address, source)
                            DO UPDATE SET
                                confidence = EXCLUDED.confidence,
                                last_seen_at = GREATEST(
                                    network_device_address_observations.last_seen_at,
                                    EXCLUDED.last_seen_at
                                )
                            """,
                            (
                                gateway_id, normalized_mac, str(parsed_address), source,
                                confidence, observed_at, observed_at,
                            ),
                        )

    def list_gateway_discovery_snapshots(self) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT gateway_id, payload, observed_at FROM gateway_discovery_snapshots "
                "ORDER BY observed_at DESC, gateway_id"
            )
            rows = cursor.fetchall()
        return [
            {"gateway_id": row[0], "payload": row[1], "observed_at": row[2]}
            for row in rows
        ]

    def list_gateway_devices(self, limit: int = 2000) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT gateway_id, mac_address, payload, first_seen_at, last_seen_at
                FROM network_devices
                ORDER BY last_seen_at DESC, gateway_id, mac_address
                LIMIT %s
                """,
                (limit,),
            )
            rows = cursor.fetchall()
        return [
            {
                "gateway_id": row[0], "mac_address": row[1], "payload": row[2],
                "first_seen_at": row[3], "last_seen_at": row[4],
            }
            for row in rows
        ]
    def list_device_identity_observations(
        self, limit: int = 10000
    ) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT gateway_id, mac_address, ip_address, source, confidence,
                       first_seen_at, last_seen_at
                FROM network_device_address_observations
                WHERE last_seen_at >= NOW() - INTERVAL '30 days'
                ORDER BY ip_address, last_seen_at DESC, gateway_id, mac_address, source
                LIMIT %s
                """,
                (limit,),
            )
            rows = cursor.fetchall()
        return [
            {
                "gateway_id": row[0],
                "mac_address": row[1],
                "ip_address": row[2],
                "source": row[3],
                "confidence": row[4],
                "first_seen_at": row[5],
                "last_seen_at": row[6],
            }
            for row in rows
        ]

    def list_events_page(self, integration_id=None, event_type=None, severity=None, limit=200, cursor=None):
        filters = []
        params = []
        if integration_id:
            filters.append("payload #>> '{source,integration_id}' = %s")
            params.append(integration_id)
        if event_type:
            filters.append("payload->>'event_type' = %s")
            params.append(event_type)
        if severity:
            filters.append("payload->>'severity' = %s")
            params.append(severity)
        if cursor:
            filters.append("(received_at, event_id) < (%s, %s)")
            params.extend(cursor)
        where = f"WHERE {' AND '.join(filters)}" if filters else ""
        params.append(limit + 1)
        with self._connect() as connection, connection.cursor() as db_cursor:
            db_cursor.execute(
                f"SELECT payload, received_at, event_id FROM events {where} "
                "ORDER BY received_at DESC, event_id DESC LIMIT %s", params
            )
            rows = db_cursor.fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        next_cursor = (rows[-1][1], rows[-1][2]) if has_more and rows else None
        return [EventEnvelope.model_validate(row[0]) for row in rows], next_cursor

    def purge_events_before(self, cutoff: datetime, batch_size: int = 1000) -> int:
        if not 1 <= batch_size <= 10000:
            raise ValueError("batch_size must be between 1 and 10000")
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """WITH doomed AS (
                    SELECT event_id FROM events WHERE received_at < %s
                    ORDER BY received_at, event_id LIMIT %s
                )
                DELETE FROM events e USING doomed d
                WHERE e.event_id = d.event_id RETURNING e.event_id""",
                (cutoff, batch_size),
            )
            return len(cursor.fetchall())

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
            SELECT last_audit_id, last_hash
            FROM audit_chain_state
            WHERE chain_id = 1
            FOR UPDATE
            """
        )
        head = cursor.fetchone()
        if head is None:
            raise StorageConfigurationError("Audit chain state is missing")
        last_audit_id, previous_hash = int(head[0]), str(head[1])

        cursor.execute(
            "SELECT nextval(pg_get_serial_sequence('audit_records', 'audit_id'))"
        )
        sequence_row = cursor.fetchone()
        if sequence_row is None:
            raise StorageConfigurationError("Audit record sequence is unavailable")
        audit_id = int(sequence_row[0])
        if audit_id <= last_audit_id:
            raise StorageConfigurationError("Audit record sequence is behind the chain head")

        occurred_at = datetime.now(UTC)
        record_hash = audit_record_hash(
            audit_id=audit_id,
            occurred_at=occurred_at,
            actor_id=actor_id,
            action=action,
            target_id=target_id,
            details=details,
            previous_hash=previous_hash,
        )
        cursor.execute(
            """
            INSERT INTO audit_records (
                audit_id, occurred_at, actor_id, action, target_id, details,
                previous_hash, record_hash
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                audit_id,
                occurred_at,
                actor_id,
                action,
                target_id,
                Jsonb(details),
                previous_hash,
                record_hash,
            ),
        )
        cursor.execute(
            """
            UPDATE audit_chain_state
            SET last_audit_id = %s, last_hash = %s
            WHERE chain_id = 1
            """,
            (audit_id, record_hash),
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
                SELECT audit_id, occurred_at, actor_id, action, target_id, details,
                       previous_hash, record_hash
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
                "previous_hash": row[6],
                "record_hash": row[7],
            }
            for row in rows
        ]


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
)
                """,
                """
                ALTER TABLE audit_records
                ADD CONSTRAINT audit_records_record_hash_check
                CHECK (record_hash ~ '^[0-9a-f]{64}            with (
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
            cursor.execute("SELECT set_config('openshield.audit_reset', 'on', true)")
            cursor.execute(
                "TRUNCATE TABLE integrations, integration_secrets, events, threat_intel_cache, "
                "incidents, incident_events, incident_investigations, policies, policy_decisions, "
                "response_executions, gateway_commands, runtime_controls, integration_poll_cursors, "
                "privacy_lists, privacy_classification_overrides, gateway_connections, "
                "gateway_discovery_snapshots, network_devices, network_device_address_observations, "
                "threat_indicators, audit_records, audit_chain_state RESTART IDENTITY CASCADE"
            )
            cursor.execute(
                """
                INSERT INTO audit_chain_state (chain_id, last_audit_id, last_hash)
                VALUES (1, 0, %s)
                """,
                (GENESIS_AUDIT_HASH,),
            )

    def create_incident_investigation(
        self, investigation_id: str, incident_id: str, provider_integration_id: str,
        provider_kind: str, model: str, prompt_version: str,
        context_scope: dict[str, object], result: dict[str, object],
    ) -> dict[str, object]:
        created_at = datetime.now(UTC)
        payload = {
            "investigation_id": investigation_id,
            "incident_id": incident_id,
            "provider_integration_id": provider_integration_id,
            "provider_kind": provider_kind,
            "model": model,
            "prompt_version": prompt_version,
            "context_scope": context_scope,
            "result": result,
            "created_at": created_at.isoformat(),
        }
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO incident_investigations
                    (investigation_id, incident_id, provider_integration_id, provider_kind,
                     model, prompt_version, context_scope, result, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    investigation_id, incident_id, provider_integration_id, provider_kind,
                    model, prompt_version, Jsonb(context_scope), Jsonb(result), created_at,
                ),
            )
            self._insert_audit(
                cursor, "incident.investigation.created", None, incident_id,
                {
                    "investigation_id": investigation_id,
                    "provider_integration_id": provider_integration_id,
                    "provider_kind": provider_kind,
                    "model": model,
                    "prompt_version": prompt_version,
                    "context_scope": context_scope,
                },
            )
        return payload

    def create_policy(self, policy: dict[str, object]) -> dict[str, object]:
        created_at = datetime.now(UTC)
        payload = {**policy, "created_at": created_at.isoformat(), "updated_at": created_at.isoformat()}
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO policies
                    (policy_id, name, enabled, indicator_type, indicator_value, action,
                     integration_id, min_risk_score, autonomy_level, ttl_seconds,
                     require_approval, direction)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    policy["policy_id"], policy["name"], policy.get("enabled", True),
                    policy["indicator_type"], policy["indicator_value"], policy["action"],
                    policy["integration_id"], policy["min_risk_score"], policy["autonomy_level"],
                    policy["ttl_seconds"], policy.get("require_approval", True),
                    policy.get("direction", "destination"),
                ),
            )
            self._insert_audit(
                cursor, "policy.created", None, str(policy["policy_id"]),
                {"action": policy["action"], "integration_id": policy["integration_id"],
                 "autonomy_level": policy["autonomy_level"], "ttl_seconds": policy["ttl_seconds"]},
            )
        return payload

    def list_policies(self, enabled_only: bool = False) -> list[dict[str, object]]:
        where = "WHERE enabled = TRUE" if enabled_only else ""
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                f"SELECT policy_id, name, enabled, indicator_type, indicator_value, action, "
                f"integration_id, min_risk_score, autonomy_level, ttl_seconds, require_approval, "
                f"direction, created_at, updated_at FROM policies {where} ORDER BY name"
            )
            rows = cursor.fetchall()
        return [
            {
                "policy_id": row[0], "name": row[1], "enabled": row[2],
                "indicator_type": row[3], "indicator_value": row[4], "action": row[5],
                "integration_id": row[6], "min_risk_score": row[7], "autonomy_level": row[8],
                "ttl_seconds": row[9], "require_approval": row[10], "direction": row[11],
                "created_at": row[12].isoformat(), "updated_at": row[13].isoformat(),
            }
            for row in rows
        ]

    def get_policy(self, policy_id: str) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT policy_id, name, enabled, indicator_type, indicator_value, action,
                       integration_id, min_risk_score, autonomy_level, ttl_seconds,
                       require_approval, direction, created_at, updated_at
                FROM policies WHERE policy_id = %s
                """,
                (policy_id,),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return {
            "policy_id": row[0], "name": row[1], "enabled": row[2],
            "indicator_type": row[3], "indicator_value": row[4], "action": row[5],
            "integration_id": row[6], "min_risk_score": row[7], "autonomy_level": row[8],
            "ttl_seconds": row[9], "require_approval": row[10], "direction": row[11],
            "created_at": row[12].isoformat(), "updated_at": row[13].isoformat(),
        }

    def update_policy(self, policy_id: str, changes: dict[str, object]) -> dict[str, object] | None:
        allowed = {
            "name", "enabled", "min_risk_score", "autonomy_level", "ttl_seconds",
            "require_approval", "direction",
        }
        updates = {key: value for key, value in changes.items() if key in allowed}
        if not updates:
            return self.get_policy(policy_id)
        assignments = ", ".join(f"{key} = %s" for key in updates)
        values = list(updates.values())
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                f"UPDATE policies SET {assignments}, updated_at = NOW() WHERE policy_id = %s",
                (*values, policy_id),
            )
            if cursor.rowcount == 0:
                return None
            self._insert_audit(cursor, "policy.updated", None, policy_id, updates)
        return self.get_policy(policy_id)

    def create_policy_decision(
        self, decision_id: str, incident_id: str, policy_id: str,
        status: str, rationale: dict[str, object],
    ) -> dict[str, object]:
        now = datetime.now(UTC)
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO policy_decisions
                    (decision_id, incident_id, policy_id, status, rationale)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (decision_id, incident_id, policy_id, status, Jsonb(rationale)),
            )
            self._insert_audit(
                cursor, "policy.decision.created", None, decision_id,
                {"incident_id": incident_id, "policy_id": policy_id, "status": status},
            )
        return {
            "decision_id": decision_id, "incident_id": incident_id,
            "policy_id": policy_id, "status": status, "rationale": rationale,
            "created_at": now.isoformat(),
        }

    def list_policy_decisions(self, limit: int = 100) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT decision_id, incident_id, policy_id, status, rationale,
                       created_at, updated_at
                FROM policy_decisions ORDER BY created_at DESC LIMIT %s
                """,
                (limit,),
            )
            rows = cursor.fetchall()
        return [
            {
                "decision_id": row[0], "incident_id": row[1], "policy_id": row[2],
                "status": row[3], "rationale": row[4],
                "created_at": row[5].isoformat(), "updated_at": row[6].isoformat(),
            }
            for row in rows
        ]

    def get_policy_decision(self, decision_id: str) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT decision_id, incident_id, policy_id, status, rationale,
                       created_at, updated_at
                FROM policy_decisions WHERE decision_id = %s
                """,
                (decision_id,),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return {
            "decision_id": row[0], "incident_id": row[1], "policy_id": row[2],
            "status": row[3], "rationale": row[4],
            "created_at": row[5].isoformat(), "updated_at": row[6].isoformat(),
        }

    def update_policy_decision(
        self, decision_id: str, status: str, rationale: dict[str, object] | None = None
    ) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT rationale FROM policy_decisions WHERE decision_id = %s FOR UPDATE",
                (decision_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            payload = {**row[0], **(rationale or {}), "status": status}
            cursor.execute(
                """
                UPDATE policy_decisions SET status = %s, rationale = %s, updated_at = NOW()
                WHERE decision_id = %s
                """,
                (status, Jsonb(payload), decision_id),
            )
            self._insert_audit(
                cursor, "policy.decision.status.updated", None, decision_id,
                {"status": status, **(rationale or {})},
            )
        return self.get_policy_decision(decision_id)

    def create_response_execution(self, execution: dict[str, object]) -> dict[str, object]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO response_executions
                    (execution_id, decision_id, incident_id, policy_id, integration_id,
                     action, indicator_type, indicator_value, direction, status, ttl_seconds,
                     expires_at, adapter_result)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    execution["execution_id"], execution["decision_id"], execution["incident_id"],
                    execution["policy_id"], execution["integration_id"], execution["action"],
                    execution["indicator_type"], execution["indicator_value"], execution["direction"],
                    execution["status"], execution["ttl_seconds"], execution.get("expires_at"),
                    Jsonb(execution.get("adapter_result", {})),
                ),
            )
            self._insert_audit(
                cursor, "response.execution.created", None, str(execution["execution_id"]),
                {"action": execution["action"], "indicator_type": execution["indicator_type"],
                 "integration_id": execution["integration_id"], "status": execution["status"],
                 "ttl_seconds": execution["ttl_seconds"]},
            )
        return execution

    @staticmethod
    def _response_execution_from_row(row: tuple[object, ...]) -> dict[str, object]:
        return {
            "execution_id": row[0], "decision_id": row[1], "incident_id": row[2],
            "policy_id": row[3], "integration_id": row[4], "action": row[5],
            "indicator_type": row[6], "indicator_value": row[7], "direction": row[8],
            "status": row[9], "ttl_seconds": row[10],
            "expires_at": row[11].isoformat() if row[11] else None,
            "adapter_result": row[12], "created_at": row[13].isoformat(),
            "rolled_back_at": row[14].isoformat() if row[14] else None,
        }

    def get_response_execution(self, execution_id: str) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT execution_id, decision_id, incident_id, policy_id, integration_id,
                       action, indicator_type, indicator_value, direction, status, ttl_seconds,
                       expires_at, adapter_result, created_at, rolled_back_at
                FROM response_executions WHERE execution_id = %s
                """,
                (execution_id,),
            )
            row = cursor.fetchone()
        return self._response_execution_from_row(row) if row is not None else None

    def update_response_execution(
        self, execution_id: str, status: str,
        adapter_result: dict[str, object] | None = None,
        expires_at: datetime | None = None, rolled_back_at: datetime | None = None,
    ) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE response_executions SET status = %s,
                    adapter_result = COALESCE(%s, adapter_result),
                    expires_at = COALESCE(%s, expires_at),
                    rolled_back_at = COALESCE(%s, rolled_back_at)
                WHERE execution_id = %s
                """,
                (
                    status, Jsonb(adapter_result) if adapter_result is not None else None,
                    expires_at, rolled_back_at, execution_id,
                ),
            )
            if cursor.rowcount == 0:
                return None
            self._insert_audit(
                cursor, "response.execution.status.updated", None, execution_id,
                {"status": status, **(adapter_result or {})},
            )
        return self.get_response_execution(execution_id)

    def list_response_executions(self, limit: int = 100) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT execution_id, decision_id, incident_id, policy_id, integration_id,
                       action, indicator_type, indicator_value, direction, status, ttl_seconds,
                       expires_at, adapter_result, created_at, rolled_back_at
                FROM response_executions
                ORDER BY created_at DESC LIMIT %s
                """,
                (limit,),
            )
            rows = cursor.fetchall()
        return [self._response_execution_from_row(row) for row in rows]

    def get_due_response_executions(self) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT execution_id, decision_id, incident_id, policy_id, integration_id,
                       action, indicator_type, indicator_value, direction, status, ttl_seconds,
                       expires_at, adapter_result, created_at, rolled_back_at
                FROM response_executions
                WHERE status IN ('active', 'rollback_failed') AND expires_at IS NOT NULL AND expires_at <= NOW()
                ORDER BY expires_at ASC LIMIT 50
                """
            )
            rows = cursor.fetchall()
        return [self._response_execution_from_row(row) for row in rows]

    def has_active_response_execution(
        self, indicator_type: str, indicator_value: str,
        integration_id: str, exclude_execution_id: str | None = None,
    ) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT 1 FROM response_executions
                WHERE indicator_type = %s AND indicator_value = %s AND integration_id = %s
                  AND status IN ('pending_gateway', 'active', 'rollback_pending', 'rollback_failed')
                  AND (%s::text IS NULL OR execution_id <> %s)
                LIMIT 1
                """,
                (indicator_type, indicator_value, integration_id, exclude_execution_id, exclude_execution_id),
            )
            return cursor.fetchone() is not None

    def enqueue_gateway_command(
        self, command_id: str, gateway_id: str, execution_id: str,
        action: str, payload: dict[str, object],
    ) -> dict[str, object]:
        now = datetime.now(UTC)
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO gateway_commands
                    (command_id, gateway_id, execution_id, action, payload, status)
                VALUES (%s, %s, %s, %s, %s, 'pending')
                """,
                (command_id, gateway_id, execution_id, action, Jsonb(payload)),
            )
            self._insert_audit(
                cursor, "gateway.command.queued", None, command_id,
                {"gateway_id": gateway_id, "execution_id": execution_id, "action": action},
            )
        return {
            "command_id": command_id, "gateway_id": gateway_id, "execution_id": execution_id,
            "action": action, "payload": payload, "status": "pending", "created_at": now.isoformat(),
        }

    def list_pending_gateway_commands(self, gateway_id: str, limit: int = 10) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT command_id, execution_id, action, payload, created_at
                FROM gateway_commands
                WHERE gateway_id = %s AND status = 'pending'
                ORDER BY created_at ASC LIMIT %s
                """,
                (gateway_id, limit),
            )
            rows = cursor.fetchall()
        return [
            {
                "command_id": row[0], "execution_id": row[1],
                "action": row[2], "payload": row[3], "created_at": row[4].isoformat(),
            }
            for row in rows
        ]

    def has_pending_gateway_command(self, execution_id: str, action: str) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT 1 FROM gateway_commands
                WHERE execution_id = %s AND action = %s AND status = 'pending'
                LIMIT 1
                """,
                (execution_id, action),
            )
            return cursor.fetchone() is not None

    def get_gateway_command(self, command_id: str) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT command_id, gateway_id, execution_id, action, payload,
                       status, result, created_at
                FROM gateway_commands WHERE command_id = %s
                """,
                (command_id,),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return {
            "command_id": row[0], "gateway_id": row[1], "execution_id": row[2],
            "action": row[3], "payload": row[4], "status": row[5],
            "result": row[6], "created_at": row[7].isoformat(),
        }

    def complete_gateway_command(
        self, command_id: str, status: str, result: dict[str, object]
    ) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT status, result FROM gateway_commands WHERE command_id = %s FOR UPDATE",
                (command_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            if row[0] == "pending":
                cursor.execute(
                    """
                    UPDATE gateway_commands SET status = %s, result = %s, updated_at = NOW()
                    WHERE command_id = %s
                    """,
                    (status, Jsonb(result), command_id),
                )
                self._insert_audit(
                    cursor, "gateway.command.completed", None, command_id,
                    {"status": status, "result_status": result.get("status")},
                )
            elif row[0] != status or row[1] != result:
                return None
        return self.get_gateway_command(command_id)

    def get_emergency_stop(self) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT value FROM runtime_controls WHERE control_key = 'emergency_stop'"
            )
            row = cursor.fetchone()
        return bool(row[0].get("active", True)) if row else True

    def set_emergency_stop(self, active: bool, actor_id: str | None = None) -> None:
        value = {"active": active}
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO runtime_controls (control_key, value)
                VALUES ('emergency_stop', %s)
                ON CONFLICT (control_key) DO UPDATE
                SET value = EXCLUDED.value, updated_at = NOW()
                """,
                (Jsonb(value),),
            )
            self._insert_audit(
                cursor, "response.emergency_stop.updated", actor_id, "emergency_stop", value,
            )

    def list_incident_investigations(
        self, incident_id: str, limit: int = 10
    ) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT investigation_id, incident_id, provider_integration_id,
                       provider_kind, model, prompt_version, context_scope, result, created_at
                FROM incident_investigations
                WHERE incident_id = %s
                ORDER BY created_at DESC LIMIT %s
                """,
                (incident_id, limit),
            )
            rows = cursor.fetchall()
        return [
            {
                "investigation_id": row[0], "incident_id": row[1],
                "provider_integration_id": row[2], "provider_kind": row[3],
                "model": row[4], "prompt_version": row[5],
                "context_scope": row[6], "result": row[7],
                "created_at": row[8].isoformat(),
            }
            for row in rows
        ]

    def get_events_by_ids(self, event_ids: list[str]) -> list[EventEnvelope]:
        if not event_ids:
            return []
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT payload FROM events WHERE event_id = ANY(%s)",
                (event_ids,),
            )
            rows = cursor.fetchall()
        return [EventEnvelope.model_validate(row[0]) for row in rows]

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

    def upsert_incident(
        self, incident: dict[str, object], event_ids: list[str],
        first_seen_at: datetime, last_seen_at: datetime,
    ) -> dict[str, object]:
        indicator_type = str(incident["indicator_type"])
        indicator_value = str(incident["indicator_value"])
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s))",
                (f"{indicator_type}:{indicator_value}",),
            )
            cursor.execute(
                """
                SELECT incident_id, status, payload, first_seen_at, last_seen_at
                FROM incidents
                WHERE indicator_type = %s AND indicator_value = %s
                FOR UPDATE
                """,
                (indicator_type, indicator_value),
            )
            row = cursor.fetchone()
            if row:
                incident_id, status, existing, old_first, old_last = row
                merged_event_ids = sorted(set(existing.get("event_ids", [])) | set(event_ids))
                merged_sources = sorted(set(existing.get("sources", [])) | set(incident.get("sources", [])))
                merged_evidence = {**existing.get("intel_evidence", {}), **incident.get("intel_evidence", {})}
                merged_source_events = {
                    item["event_id"]: item
                    for item in [*existing.get("source_events", []), *incident.get("source_events", [])]
                    if isinstance(item, dict) and isinstance(item.get("event_id"), str)
                }
                payload = {
                    **existing, **incident, "incident_id": incident_id,
                    "status": status, "event_ids": merged_event_ids,
                    "sources": merged_sources, "intel_evidence": merged_evidence,
                    "source_events": list(merged_source_events.values()),
                    "created_at": existing.get("created_at", incident.get("created_at")),
                }
                old_score = int(existing.get("risk_score", 0))
                if old_score > int(incident["risk_score"]):
                    payload["risk_score"] = old_score
                    payload["risk_level"] = existing.get("risk_level", incident.get("risk_level"))
                    payload["risk_factors"] = existing.get("risk_factors", incident.get("risk_factors", []))
                if status == "closed" and set(event_ids) - set(existing.get("event_ids", [])):
                    status = "open"
                    payload["status"] = status
                first_seen = min(old_first, first_seen_at)
                last_seen = max(old_last, last_seen_at)
                cursor.execute(
                    """
                    UPDATE incidents SET status = %s, risk_score = %s, payload = %s,
                        first_seen_at = %s, last_seen_at = %s, updated_at = NOW()
                    WHERE incident_id = %s
                    """,
                    (status, int(payload["risk_score"]), Jsonb(payload), first_seen, last_seen, incident_id),
                )
                action = "incident.updated"
            else:
                incident_id = str(incident["incident_id"])
                status = str(incident.get("status", "open"))
                payload = {**incident, "incident_id": incident_id, "status": status,
                           "event_ids": sorted(set(event_ids))}
                first_seen, last_seen = first_seen_at, last_seen_at
                cursor.execute(
                    """
                    INSERT INTO incidents
                        (incident_id, indicator_type, indicator_value, status, risk_score,
                         payload, first_seen_at, last_seen_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (incident_id, indicator_type, indicator_value, status,
                     int(payload["risk_score"]), Jsonb(payload), first_seen, last_seen),
                )
                action = "incident.created"
            for event_id in event_ids:
                cursor.execute(
                    """
                    INSERT INTO incident_events (incident_id, event_id)
                    VALUES (%s, %s) ON CONFLICT DO NOTHING
                    """,
                    (incident_id, event_id),
                )
            self._insert_audit(
                cursor, action, None, incident_id,
                {"indicator_type": indicator_type, "indicator_value": indicator_value,
                 "risk_score": int(payload["risk_score"]), "event_count": len(payload["event_ids"])},
            )
        return payload

    def list_incidents(
        self, limit: int = 100, status: str | None = None
    ) -> list[dict[str, object]]:
        filters = "WHERE status = %s" if status else ""
        params = (status, limit) if status else (limit,)
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                f"SELECT payload FROM incidents {filters} "
                "ORDER BY risk_score DESC, last_seen_at DESC LIMIT %s",
                params,
            )
            rows = cursor.fetchall()
        return [row[0] for row in rows]

    def get_incident(self, incident_id: str) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT payload FROM incidents WHERE incident_id = %s", (incident_id,)
            )
            row = cursor.fetchone()
        return row[0] if row else None

    def get_incident_events(self, incident_id: str) -> list[EventEnvelope]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT e.payload FROM incident_events ie
                JOIN events e ON e.event_id = ie.event_id
                WHERE ie.incident_id = %s
                ORDER BY e.received_at ASC, e.event_id ASC
                """,
                (incident_id,),
            )
            rows = cursor.fetchall()
        return [EventEnvelope.model_validate(row[0]) for row in rows]

    def update_incident_status(
        self, incident_id: str, status: str, reason: str = ""
    ) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT payload FROM incidents WHERE incident_id = %s FOR UPDATE",
                (incident_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            payload = {**row[0], "status": status, "status_reason": reason}
            cursor.execute(
                """
                UPDATE incidents SET status = %s, payload = %s, updated_at = NOW()
                WHERE incident_id = %s
                """,
                (status, Jsonb(payload), incident_id),
            )
            self._insert_audit(
                cursor, "incident.status.updated", None, incident_id,
                {"status": status, "reason": reason[:200]},
            )
        return payload

    def set_integration_secret(self, integration_id: str, encrypted_value: bytes) -> None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO integration_secrets (integration_id, encrypted_value)
                VALUES (%s, %s)
                ON CONFLICT (integration_id) DO UPDATE
                SET encrypted_value = EXCLUDED.encrypted_value, updated_at = NOW()
                """,
                (integration_id, encrypted_value),
            )
            self._insert_audit(
                cursor, "integration.secret.updated", None, integration_id,
                {"encrypted": True},
            )

    def get_integration_secret(self, integration_id: str) -> bytes | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT encrypted_value FROM integration_secrets WHERE integration_id = %s",
                (integration_id,),
            )
            row = cursor.fetchone()
        return bytes(row[0]) if row else None

    def list_integration_secret_ids(self) -> list[str]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT integration_id FROM integration_secrets ORDER BY integration_id"
            )
            rows = cursor.fetchall()
        return [str(row[0]) for row in rows]

    def delete_integration_secret(self, integration_id: str) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM integration_secrets WHERE integration_id = %s RETURNING integration_id",
                (integration_id,),
            )
            deleted = cursor.fetchone() is not None
            if deleted:
                self._insert_audit(
                    cursor, "integration.secret.deleted", None, integration_id, {},
                )
            return deleted

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

    def update_integration(
        self, integration: Integration, actor_id: str | None = None
    ) -> Integration | None:
        payload = integration.model_dump(mode="json")
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE integrations SET payload = %s
                WHERE integration_id = %s
                RETURNING integration_id
                """,
                (Jsonb(payload), integration.integration_id),
            )
            if cursor.fetchone() is None:
                return None
            self._insert_audit(
                cursor, "integration.updated", actor_id, integration.integration_id,
                {"kind": integration.kind},
            )
        return integration

    def delete_integration(
        self, integration_id: str, actor_id: str | None = None
    ) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM integrations WHERE integration_id = %s RETURNING payload",
                (integration_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return False
            integration = Integration.model_validate(row[0])
            self._insert_audit(
                cursor, "integration.deleted", actor_id, integration_id,
                {"kind": integration.kind, "history_preserved": True},
            )
        return True

    def get_integration_poll_cursor(self, integration_id: str) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT cursor FROM integration_poll_cursors WHERE integration_id = %s",
                (integration_id,),
            )
            row = cursor.fetchone()
        return row[0] if row else None

    def delete_integration_poll_cursor(self, integration_id: str) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM integration_poll_cursors WHERE integration_id = %s RETURNING integration_id",
                (integration_id,),
            )
            return cursor.fetchone() is not None

    def set_integration_poll_cursor(
        self, integration_id: str, provider_kind: str, value: dict[str, object]
    ) -> None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO integration_poll_cursors (integration_id, provider_kind, cursor)
                VALUES (%s, %s, %s)
                ON CONFLICT (integration_id) DO UPDATE
                SET provider_kind = EXCLUDED.provider_kind,
                    cursor = EXCLUDED.cursor, updated_at = NOW()
                """,
                (integration_id, provider_kind, Jsonb(value)),
            )

    def checkpoint_integration_poll_page(
        self,
        integration_id: str,
        provider_kind: str,
        value: dict[str, object],
        completion_details: dict[str, object],
        rejection_details: dict[str, object] | None = None,
    ) -> None:
        """Atomically persist page diagnostics and advance its provider cursor."""
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO integration_poll_cursors (integration_id, provider_kind, cursor)
                VALUES (%s, %s, %s)
                ON CONFLICT (integration_id) DO UPDATE
                SET provider_kind = EXCLUDED.provider_kind,
                    cursor = EXCLUDED.cursor, updated_at = NOW()
                """,
                (integration_id, provider_kind, Jsonb(value)),
            )
            if rejection_details is not None:
                self._insert_audit(
                    cursor, "privacy.provider_poll.records_rejected", None,
                    integration_id, rejection_details,
                )
            self._insert_audit(
                cursor, "privacy.provider_poll.completed", None,
                integration_id, completion_details,
            )

    def insert_event(self, event: EventEnvelope, actor_id: str | None = None) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO events (event_id, payload, occurred_at)
                VALUES (%s, %s, %s)
                ON CONFLICT (event_id) DO NOTHING
                RETURNING event_id
                """,
                (
                    event.event_id,
                    Jsonb(event.model_dump(mode="json")),
                    event.occurred_at,
                ),
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

    def record_gateway_discovery(
        self, gateway_id: str, payload: dict[str, object], observed_at: datetime
    ) -> None:
        snapshot = {
            "board": payload.get("board", {}),
            "interfaces": payload.get("interfaces", []),
            "device_discovery": payload.get("device_discovery", {}),
        }
        devices = payload.get("devices", [])
        if not isinstance(devices, list):
            devices = []
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO gateway_discovery_snapshots (gateway_id, payload, observed_at)
                VALUES (%s, %s, %s)
                ON CONFLICT (gateway_id) DO UPDATE
                SET payload = CASE
                        WHEN EXCLUDED.observed_at >= gateway_discovery_snapshots.observed_at
                        THEN EXCLUDED.payload ELSE gateway_discovery_snapshots.payload END,
                    observed_at = GREATEST(
                        gateway_discovery_snapshots.observed_at, EXCLUDED.observed_at
                    )
                """,
                (gateway_id, Jsonb(snapshot), observed_at),
            )
            for device in devices:
                if not isinstance(device, dict):
                    continue
                mac = device.get("mac_address")
                if not isinstance(mac, str) or not re.fullmatch(
                    r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac
                ):
                    continue
                if not _has_valid_device_address(device):
                    continue
                normalized_mac = mac.lower()
                cursor.execute(
                    """
                    INSERT INTO network_devices (
                        gateway_id, mac_address, payload, first_seen_at, last_seen_at
                    ) VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (gateway_id, mac_address) DO UPDATE
                    SET payload = CASE
                            WHEN EXCLUDED.last_seen_at >= network_devices.last_seen_at
                            THEN EXCLUDED.payload ELSE network_devices.payload END,
                        last_seen_at = GREATEST(
                            network_devices.last_seen_at, EXCLUDED.last_seen_at
                        )
                    """,
                    (gateway_id, normalized_mac, Jsonb(device), observed_at, observed_at),
                )
                address_evidence = device.get("address_evidence")
                if not isinstance(address_evidence, dict):
                    address_evidence = {}
                    for field in ("ipv4_addresses", "ipv6_addresses"):
                        addresses = device.get(field, [])
                        if isinstance(addresses, list):
                            for address in addresses:
                                if isinstance(address, str):
                                    address_evidence.setdefault(address, []).append({
                                        "source": "luci_host_hints",
                                        "confidence": "medium",
                                    })
                for address, evidence_items in address_evidence.items():
                    if not isinstance(address, str) or not isinstance(evidence_items, list):
                        continue
                    try:
                        parsed_address = ipaddress.ip_address(address)
                    except ValueError:
                        continue
                    if (
                        parsed_address.is_unspecified
                        or parsed_address.is_multicast
                        or parsed_address.is_loopback
                    ):
                        continue
                    for evidence in evidence_items:
                        if not isinstance(evidence, dict):
                            continue
                        source = evidence.get("source")
                        confidence = evidence.get("confidence")
                        if source not in {"luci_host_hints", "dhcp_lease"}:
                            continue
                        expected_confidence = (
                            "high" if source == "dhcp_lease" else "medium"
                        )
                        if confidence != expected_confidence:
                            confidence = expected_confidence
                        cursor.execute(
                            """
                            INSERT INTO network_device_address_observations (
                                gateway_id, mac_address, ip_address, source, confidence,
                                first_seen_at, last_seen_at
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (gateway_id, mac_address, ip_address, source)
                            DO UPDATE SET
                                confidence = EXCLUDED.confidence,
                                last_seen_at = GREATEST(
                                    network_device_address_observations.last_seen_at,
                                    EXCLUDED.last_seen_at
                                )
                            """,
                            (
                                gateway_id, normalized_mac, str(parsed_address), source,
                                confidence, observed_at, observed_at,
                            ),
                        )

    def list_gateway_discovery_snapshots(self) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT gateway_id, payload, observed_at FROM gateway_discovery_snapshots "
                "ORDER BY observed_at DESC, gateway_id"
            )
            rows = cursor.fetchall()
        return [
            {"gateway_id": row[0], "payload": row[1], "observed_at": row[2]}
            for row in rows
        ]

    def list_gateway_devices(self, limit: int = 2000) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT gateway_id, mac_address, payload, first_seen_at, last_seen_at
                FROM network_devices
                ORDER BY last_seen_at DESC, gateway_id, mac_address
                LIMIT %s
                """,
                (limit,),
            )
            rows = cursor.fetchall()
        return [
            {
                "gateway_id": row[0], "mac_address": row[1], "payload": row[2],
                "first_seen_at": row[3], "last_seen_at": row[4],
            }
            for row in rows
        ]
    def list_device_identity_observations(
        self, limit: int = 10000
    ) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT gateway_id, mac_address, ip_address, source, confidence,
                       first_seen_at, last_seen_at
                FROM network_device_address_observations
                WHERE last_seen_at >= NOW() - INTERVAL '30 days'
                ORDER BY ip_address, last_seen_at DESC, gateway_id, mac_address, source
                LIMIT %s
                """,
                (limit,),
            )
            rows = cursor.fetchall()
        return [
            {
                "gateway_id": row[0],
                "mac_address": row[1],
                "ip_address": row[2],
                "source": row[3],
                "confidence": row[4],
                "first_seen_at": row[5],
                "last_seen_at": row[6],
            }
            for row in rows
        ]

    def list_events_page(self, integration_id=None, event_type=None, severity=None, limit=200, cursor=None):
        filters = []
        params = []
        if integration_id:
            filters.append("payload #>> '{source,integration_id}' = %s")
            params.append(integration_id)
        if event_type:
            filters.append("payload->>'event_type' = %s")
            params.append(event_type)
        if severity:
            filters.append("payload->>'severity' = %s")
            params.append(severity)
        if cursor:
            filters.append("(received_at, event_id) < (%s, %s)")
            params.extend(cursor)
        where = f"WHERE {' AND '.join(filters)}" if filters else ""
        params.append(limit + 1)
        with self._connect() as connection, connection.cursor() as db_cursor:
            db_cursor.execute(
                f"SELECT payload, received_at, event_id FROM events {where} "
                "ORDER BY received_at DESC, event_id DESC LIMIT %s", params
            )
            rows = db_cursor.fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        next_cursor = (rows[-1][1], rows[-1][2]) if has_more and rows else None
        return [EventEnvelope.model_validate(row[0]) for row in rows], next_cursor

    def purge_events_before(self, cutoff: datetime, batch_size: int = 1000) -> int:
        if not 1 <= batch_size <= 10000:
            raise ValueError("batch_size must be between 1 and 10000")
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """WITH doomed AS (
                    SELECT event_id FROM events WHERE received_at < %s
                    ORDER BY received_at, event_id LIMIT %s
                )
                DELETE FROM events e USING doomed d
                WHERE e.event_id = d.event_id RETURNING e.event_id""",
                (cutoff, batch_size),
            )
            return len(cursor.fetchall())

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
            SELECT last_audit_id, last_hash
            FROM audit_chain_state
            WHERE chain_id = 1
            FOR UPDATE
            """
        )
        head = cursor.fetchone()
        if head is None:
            raise StorageConfigurationError("Audit chain state is missing")
        last_audit_id, previous_hash = int(head[0]), str(head[1])

        cursor.execute(
            "SELECT nextval(pg_get_serial_sequence('audit_records', 'audit_id'))"
        )
        sequence_row = cursor.fetchone()
        if sequence_row is None:
            raise StorageConfigurationError("Audit record sequence is unavailable")
        audit_id = int(sequence_row[0])
        if audit_id <= last_audit_id:
            raise StorageConfigurationError("Audit record sequence is behind the chain head")

        occurred_at = datetime.now(UTC)
        record_hash = audit_record_hash(
            audit_id=audit_id,
            occurred_at=occurred_at,
            actor_id=actor_id,
            action=action,
            target_id=target_id,
            details=details,
            previous_hash=previous_hash,
        )
        cursor.execute(
            """
            INSERT INTO audit_records (
                audit_id, occurred_at, actor_id, action, target_id, details,
                previous_hash, record_hash
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                audit_id,
                occurred_at,
                actor_id,
                action,
                target_id,
                Jsonb(details),
                previous_hash,
                record_hash,
            ),
        )
        cursor.execute(
            """
            UPDATE audit_chain_state
            SET last_audit_id = %s, last_hash = %s
            WHERE chain_id = 1
            """,
            (audit_id, record_hash),
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
                SELECT audit_id, occurred_at, actor_id, action, target_id, details,
                       previous_hash, record_hash
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
                "previous_hash": row[6],
                "record_hash": row[7],
            }
            for row in rows
        ]


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
)
                """,
                """
                CREATE OR REPLACE FUNCTION openshield_guard_audit_record_mutation()
                RETURNS trigger
                LANGUAGE plpgsql
                AS $
                BEGIN
                    IF current_setting('openshield.audit_reset', true) = 'on' THEN
                        RETURN OLD;
                    END IF;
                    RAISE EXCEPTION 'audit_records are append-only';
                END;
                $
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
                AS $
                BEGIN
                    IF current_setting('openshield.audit_reset', true) IS DISTINCT FROM 'on' THEN
                        RAISE EXCEPTION 'audit_records cannot be truncated';
                    END IF;
                    RETURN NULL;
                END;
                $
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
            cursor.execute("SELECT set_config('openshield.audit_reset', 'on', true)")
            cursor.execute(
                "TRUNCATE TABLE integrations, integration_secrets, events, threat_intel_cache, "
                "incidents, incident_events, incident_investigations, policies, policy_decisions, "
                "response_executions, gateway_commands, runtime_controls, integration_poll_cursors, "
                "privacy_lists, privacy_classification_overrides, gateway_connections, "
                "gateway_discovery_snapshots, network_devices, network_device_address_observations, "
                "threat_indicators, audit_records, audit_chain_state RESTART IDENTITY CASCADE"
            )
            cursor.execute(
                """
                INSERT INTO audit_chain_state (chain_id, last_audit_id, last_hash)
                VALUES (1, 0, %s)
                """,
                (GENESIS_AUDIT_HASH,),
            )

    def create_incident_investigation(
        self, investigation_id: str, incident_id: str, provider_integration_id: str,
        provider_kind: str, model: str, prompt_version: str,
        context_scope: dict[str, object], result: dict[str, object],
    ) -> dict[str, object]:
        created_at = datetime.now(UTC)
        payload = {
            "investigation_id": investigation_id,
            "incident_id": incident_id,
            "provider_integration_id": provider_integration_id,
            "provider_kind": provider_kind,
            "model": model,
            "prompt_version": prompt_version,
            "context_scope": context_scope,
            "result": result,
            "created_at": created_at.isoformat(),
        }
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO incident_investigations
                    (investigation_id, incident_id, provider_integration_id, provider_kind,
                     model, prompt_version, context_scope, result, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    investigation_id, incident_id, provider_integration_id, provider_kind,
                    model, prompt_version, Jsonb(context_scope), Jsonb(result), created_at,
                ),
            )
            self._insert_audit(
                cursor, "incident.investigation.created", None, incident_id,
                {
                    "investigation_id": investigation_id,
                    "provider_integration_id": provider_integration_id,
                    "provider_kind": provider_kind,
                    "model": model,
                    "prompt_version": prompt_version,
                    "context_scope": context_scope,
                },
            )
        return payload

    def create_policy(self, policy: dict[str, object]) -> dict[str, object]:
        created_at = datetime.now(UTC)
        payload = {**policy, "created_at": created_at.isoformat(), "updated_at": created_at.isoformat()}
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO policies
                    (policy_id, name, enabled, indicator_type, indicator_value, action,
                     integration_id, min_risk_score, autonomy_level, ttl_seconds,
                     require_approval, direction)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    policy["policy_id"], policy["name"], policy.get("enabled", True),
                    policy["indicator_type"], policy["indicator_value"], policy["action"],
                    policy["integration_id"], policy["min_risk_score"], policy["autonomy_level"],
                    policy["ttl_seconds"], policy.get("require_approval", True),
                    policy.get("direction", "destination"),
                ),
            )
            self._insert_audit(
                cursor, "policy.created", None, str(policy["policy_id"]),
                {"action": policy["action"], "integration_id": policy["integration_id"],
                 "autonomy_level": policy["autonomy_level"], "ttl_seconds": policy["ttl_seconds"]},
            )
        return payload

    def list_policies(self, enabled_only: bool = False) -> list[dict[str, object]]:
        where = "WHERE enabled = TRUE" if enabled_only else ""
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                f"SELECT policy_id, name, enabled, indicator_type, indicator_value, action, "
                f"integration_id, min_risk_score, autonomy_level, ttl_seconds, require_approval, "
                f"direction, created_at, updated_at FROM policies {where} ORDER BY name"
            )
            rows = cursor.fetchall()
        return [
            {
                "policy_id": row[0], "name": row[1], "enabled": row[2],
                "indicator_type": row[3], "indicator_value": row[4], "action": row[5],
                "integration_id": row[6], "min_risk_score": row[7], "autonomy_level": row[8],
                "ttl_seconds": row[9], "require_approval": row[10], "direction": row[11],
                "created_at": row[12].isoformat(), "updated_at": row[13].isoformat(),
            }
            for row in rows
        ]

    def get_policy(self, policy_id: str) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT policy_id, name, enabled, indicator_type, indicator_value, action,
                       integration_id, min_risk_score, autonomy_level, ttl_seconds,
                       require_approval, direction, created_at, updated_at
                FROM policies WHERE policy_id = %s
                """,
                (policy_id,),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return {
            "policy_id": row[0], "name": row[1], "enabled": row[2],
            "indicator_type": row[3], "indicator_value": row[4], "action": row[5],
            "integration_id": row[6], "min_risk_score": row[7], "autonomy_level": row[8],
            "ttl_seconds": row[9], "require_approval": row[10], "direction": row[11],
            "created_at": row[12].isoformat(), "updated_at": row[13].isoformat(),
        }

    def update_policy(self, policy_id: str, changes: dict[str, object]) -> dict[str, object] | None:
        allowed = {
            "name", "enabled", "min_risk_score", "autonomy_level", "ttl_seconds",
            "require_approval", "direction",
        }
        updates = {key: value for key, value in changes.items() if key in allowed}
        if not updates:
            return self.get_policy(policy_id)
        assignments = ", ".join(f"{key} = %s" for key in updates)
        values = list(updates.values())
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                f"UPDATE policies SET {assignments}, updated_at = NOW() WHERE policy_id = %s",
                (*values, policy_id),
            )
            if cursor.rowcount == 0:
                return None
            self._insert_audit(cursor, "policy.updated", None, policy_id, updates)
        return self.get_policy(policy_id)

    def create_policy_decision(
        self, decision_id: str, incident_id: str, policy_id: str,
        status: str, rationale: dict[str, object],
    ) -> dict[str, object]:
        now = datetime.now(UTC)
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO policy_decisions
                    (decision_id, incident_id, policy_id, status, rationale)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (decision_id, incident_id, policy_id, status, Jsonb(rationale)),
            )
            self._insert_audit(
                cursor, "policy.decision.created", None, decision_id,
                {"incident_id": incident_id, "policy_id": policy_id, "status": status},
            )
        return {
            "decision_id": decision_id, "incident_id": incident_id,
            "policy_id": policy_id, "status": status, "rationale": rationale,
            "created_at": now.isoformat(),
        }

    def list_policy_decisions(self, limit: int = 100) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT decision_id, incident_id, policy_id, status, rationale,
                       created_at, updated_at
                FROM policy_decisions ORDER BY created_at DESC LIMIT %s
                """,
                (limit,),
            )
            rows = cursor.fetchall()
        return [
            {
                "decision_id": row[0], "incident_id": row[1], "policy_id": row[2],
                "status": row[3], "rationale": row[4],
                "created_at": row[5].isoformat(), "updated_at": row[6].isoformat(),
            }
            for row in rows
        ]

    def get_policy_decision(self, decision_id: str) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT decision_id, incident_id, policy_id, status, rationale,
                       created_at, updated_at
                FROM policy_decisions WHERE decision_id = %s
                """,
                (decision_id,),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return {
            "decision_id": row[0], "incident_id": row[1], "policy_id": row[2],
            "status": row[3], "rationale": row[4],
            "created_at": row[5].isoformat(), "updated_at": row[6].isoformat(),
        }

    def update_policy_decision(
        self, decision_id: str, status: str, rationale: dict[str, object] | None = None
    ) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT rationale FROM policy_decisions WHERE decision_id = %s FOR UPDATE",
                (decision_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            payload = {**row[0], **(rationale or {}), "status": status}
            cursor.execute(
                """
                UPDATE policy_decisions SET status = %s, rationale = %s, updated_at = NOW()
                WHERE decision_id = %s
                """,
                (status, Jsonb(payload), decision_id),
            )
            self._insert_audit(
                cursor, "policy.decision.status.updated", None, decision_id,
                {"status": status, **(rationale or {})},
            )
        return self.get_policy_decision(decision_id)

    def create_response_execution(self, execution: dict[str, object]) -> dict[str, object]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO response_executions
                    (execution_id, decision_id, incident_id, policy_id, integration_id,
                     action, indicator_type, indicator_value, direction, status, ttl_seconds,
                     expires_at, adapter_result)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    execution["execution_id"], execution["decision_id"], execution["incident_id"],
                    execution["policy_id"], execution["integration_id"], execution["action"],
                    execution["indicator_type"], execution["indicator_value"], execution["direction"],
                    execution["status"], execution["ttl_seconds"], execution.get("expires_at"),
                    Jsonb(execution.get("adapter_result", {})),
                ),
            )
            self._insert_audit(
                cursor, "response.execution.created", None, str(execution["execution_id"]),
                {"action": execution["action"], "indicator_type": execution["indicator_type"],
                 "integration_id": execution["integration_id"], "status": execution["status"],
                 "ttl_seconds": execution["ttl_seconds"]},
            )
        return execution

    @staticmethod
    def _response_execution_from_row(row: tuple[object, ...]) -> dict[str, object]:
        return {
            "execution_id": row[0], "decision_id": row[1], "incident_id": row[2],
            "policy_id": row[3], "integration_id": row[4], "action": row[5],
            "indicator_type": row[6], "indicator_value": row[7], "direction": row[8],
            "status": row[9], "ttl_seconds": row[10],
            "expires_at": row[11].isoformat() if row[11] else None,
            "adapter_result": row[12], "created_at": row[13].isoformat(),
            "rolled_back_at": row[14].isoformat() if row[14] else None,
        }

    def get_response_execution(self, execution_id: str) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT execution_id, decision_id, incident_id, policy_id, integration_id,
                       action, indicator_type, indicator_value, direction, status, ttl_seconds,
                       expires_at, adapter_result, created_at, rolled_back_at
                FROM response_executions WHERE execution_id = %s
                """,
                (execution_id,),
            )
            row = cursor.fetchone()
        return self._response_execution_from_row(row) if row is not None else None

    def update_response_execution(
        self, execution_id: str, status: str,
        adapter_result: dict[str, object] | None = None,
        expires_at: datetime | None = None, rolled_back_at: datetime | None = None,
    ) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE response_executions SET status = %s,
                    adapter_result = COALESCE(%s, adapter_result),
                    expires_at = COALESCE(%s, expires_at),
                    rolled_back_at = COALESCE(%s, rolled_back_at)
                WHERE execution_id = %s
                """,
                (
                    status, Jsonb(adapter_result) if adapter_result is not None else None,
                    expires_at, rolled_back_at, execution_id,
                ),
            )
            if cursor.rowcount == 0:
                return None
            self._insert_audit(
                cursor, "response.execution.status.updated", None, execution_id,
                {"status": status, **(adapter_result or {})},
            )
        return self.get_response_execution(execution_id)

    def list_response_executions(self, limit: int = 100) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT execution_id, decision_id, incident_id, policy_id, integration_id,
                       action, indicator_type, indicator_value, direction, status, ttl_seconds,
                       expires_at, adapter_result, created_at, rolled_back_at
                FROM response_executions
                ORDER BY created_at DESC LIMIT %s
                """,
                (limit,),
            )
            rows = cursor.fetchall()
        return [self._response_execution_from_row(row) for row in rows]

    def get_due_response_executions(self) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT execution_id, decision_id, incident_id, policy_id, integration_id,
                       action, indicator_type, indicator_value, direction, status, ttl_seconds,
                       expires_at, adapter_result, created_at, rolled_back_at
                FROM response_executions
                WHERE status IN ('active', 'rollback_failed') AND expires_at IS NOT NULL AND expires_at <= NOW()
                ORDER BY expires_at ASC LIMIT 50
                """
            )
            rows = cursor.fetchall()
        return [self._response_execution_from_row(row) for row in rows]

    def has_active_response_execution(
        self, indicator_type: str, indicator_value: str,
        integration_id: str, exclude_execution_id: str | None = None,
    ) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT 1 FROM response_executions
                WHERE indicator_type = %s AND indicator_value = %s AND integration_id = %s
                  AND status IN ('pending_gateway', 'active', 'rollback_pending', 'rollback_failed')
                  AND (%s::text IS NULL OR execution_id <> %s)
                LIMIT 1
                """,
                (indicator_type, indicator_value, integration_id, exclude_execution_id, exclude_execution_id),
            )
            return cursor.fetchone() is not None

    def enqueue_gateway_command(
        self, command_id: str, gateway_id: str, execution_id: str,
        action: str, payload: dict[str, object],
    ) -> dict[str, object]:
        now = datetime.now(UTC)
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO gateway_commands
                    (command_id, gateway_id, execution_id, action, payload, status)
                VALUES (%s, %s, %s, %s, %s, 'pending')
                """,
                (command_id, gateway_id, execution_id, action, Jsonb(payload)),
            )
            self._insert_audit(
                cursor, "gateway.command.queued", None, command_id,
                {"gateway_id": gateway_id, "execution_id": execution_id, "action": action},
            )
        return {
            "command_id": command_id, "gateway_id": gateway_id, "execution_id": execution_id,
            "action": action, "payload": payload, "status": "pending", "created_at": now.isoformat(),
        }

    def list_pending_gateway_commands(self, gateway_id: str, limit: int = 10) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT command_id, execution_id, action, payload, created_at
                FROM gateway_commands
                WHERE gateway_id = %s AND status = 'pending'
                ORDER BY created_at ASC LIMIT %s
                """,
                (gateway_id, limit),
            )
            rows = cursor.fetchall()
        return [
            {
                "command_id": row[0], "execution_id": row[1],
                "action": row[2], "payload": row[3], "created_at": row[4].isoformat(),
            }
            for row in rows
        ]

    def has_pending_gateway_command(self, execution_id: str, action: str) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT 1 FROM gateway_commands
                WHERE execution_id = %s AND action = %s AND status = 'pending'
                LIMIT 1
                """,
                (execution_id, action),
            )
            return cursor.fetchone() is not None

    def get_gateway_command(self, command_id: str) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT command_id, gateway_id, execution_id, action, payload,
                       status, result, created_at
                FROM gateway_commands WHERE command_id = %s
                """,
                (command_id,),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return {
            "command_id": row[0], "gateway_id": row[1], "execution_id": row[2],
            "action": row[3], "payload": row[4], "status": row[5],
            "result": row[6], "created_at": row[7].isoformat(),
        }

    def complete_gateway_command(
        self, command_id: str, status: str, result: dict[str, object]
    ) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT status, result FROM gateway_commands WHERE command_id = %s FOR UPDATE",
                (command_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            if row[0] == "pending":
                cursor.execute(
                    """
                    UPDATE gateway_commands SET status = %s, result = %s, updated_at = NOW()
                    WHERE command_id = %s
                    """,
                    (status, Jsonb(result), command_id),
                )
                self._insert_audit(
                    cursor, "gateway.command.completed", None, command_id,
                    {"status": status, "result_status": result.get("status")},
                )
            elif row[0] != status or row[1] != result:
                return None
        return self.get_gateway_command(command_id)

    def get_emergency_stop(self) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT value FROM runtime_controls WHERE control_key = 'emergency_stop'"
            )
            row = cursor.fetchone()
        return bool(row[0].get("active", True)) if row else True

    def set_emergency_stop(self, active: bool, actor_id: str | None = None) -> None:
        value = {"active": active}
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO runtime_controls (control_key, value)
                VALUES ('emergency_stop', %s)
                ON CONFLICT (control_key) DO UPDATE
                SET value = EXCLUDED.value, updated_at = NOW()
                """,
                (Jsonb(value),),
            )
            self._insert_audit(
                cursor, "response.emergency_stop.updated", actor_id, "emergency_stop", value,
            )

    def list_incident_investigations(
        self, incident_id: str, limit: int = 10
    ) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT investigation_id, incident_id, provider_integration_id,
                       provider_kind, model, prompt_version, context_scope, result, created_at
                FROM incident_investigations
                WHERE incident_id = %s
                ORDER BY created_at DESC LIMIT %s
                """,
                (incident_id, limit),
            )
            rows = cursor.fetchall()
        return [
            {
                "investigation_id": row[0], "incident_id": row[1],
                "provider_integration_id": row[2], "provider_kind": row[3],
                "model": row[4], "prompt_version": row[5],
                "context_scope": row[6], "result": row[7],
                "created_at": row[8].isoformat(),
            }
            for row in rows
        ]

    def get_events_by_ids(self, event_ids: list[str]) -> list[EventEnvelope]:
        if not event_ids:
            return []
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT payload FROM events WHERE event_id = ANY(%s)",
                (event_ids,),
            )
            rows = cursor.fetchall()
        return [EventEnvelope.model_validate(row[0]) for row in rows]

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

    def upsert_incident(
        self, incident: dict[str, object], event_ids: list[str],
        first_seen_at: datetime, last_seen_at: datetime,
    ) -> dict[str, object]:
        indicator_type = str(incident["indicator_type"])
        indicator_value = str(incident["indicator_value"])
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s))",
                (f"{indicator_type}:{indicator_value}",),
            )
            cursor.execute(
                """
                SELECT incident_id, status, payload, first_seen_at, last_seen_at
                FROM incidents
                WHERE indicator_type = %s AND indicator_value = %s
                FOR UPDATE
                """,
                (indicator_type, indicator_value),
            )
            row = cursor.fetchone()
            if row:
                incident_id, status, existing, old_first, old_last = row
                merged_event_ids = sorted(set(existing.get("event_ids", [])) | set(event_ids))
                merged_sources = sorted(set(existing.get("sources", [])) | set(incident.get("sources", [])))
                merged_evidence = {**existing.get("intel_evidence", {}), **incident.get("intel_evidence", {})}
                merged_source_events = {
                    item["event_id"]: item
                    for item in [*existing.get("source_events", []), *incident.get("source_events", [])]
                    if isinstance(item, dict) and isinstance(item.get("event_id"), str)
                }
                payload = {
                    **existing, **incident, "incident_id": incident_id,
                    "status": status, "event_ids": merged_event_ids,
                    "sources": merged_sources, "intel_evidence": merged_evidence,
                    "source_events": list(merged_source_events.values()),
                    "created_at": existing.get("created_at", incident.get("created_at")),
                }
                old_score = int(existing.get("risk_score", 0))
                if old_score > int(incident["risk_score"]):
                    payload["risk_score"] = old_score
                    payload["risk_level"] = existing.get("risk_level", incident.get("risk_level"))
                    payload["risk_factors"] = existing.get("risk_factors", incident.get("risk_factors", []))
                if status == "closed" and set(event_ids) - set(existing.get("event_ids", [])):
                    status = "open"
                    payload["status"] = status
                first_seen = min(old_first, first_seen_at)
                last_seen = max(old_last, last_seen_at)
                cursor.execute(
                    """
                    UPDATE incidents SET status = %s, risk_score = %s, payload = %s,
                        first_seen_at = %s, last_seen_at = %s, updated_at = NOW()
                    WHERE incident_id = %s
                    """,
                    (status, int(payload["risk_score"]), Jsonb(payload), first_seen, last_seen, incident_id),
                )
                action = "incident.updated"
            else:
                incident_id = str(incident["incident_id"])
                status = str(incident.get("status", "open"))
                payload = {**incident, "incident_id": incident_id, "status": status,
                           "event_ids": sorted(set(event_ids))}
                first_seen, last_seen = first_seen_at, last_seen_at
                cursor.execute(
                    """
                    INSERT INTO incidents
                        (incident_id, indicator_type, indicator_value, status, risk_score,
                         payload, first_seen_at, last_seen_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (incident_id, indicator_type, indicator_value, status,
                     int(payload["risk_score"]), Jsonb(payload), first_seen, last_seen),
                )
                action = "incident.created"
            for event_id in event_ids:
                cursor.execute(
                    """
                    INSERT INTO incident_events (incident_id, event_id)
                    VALUES (%s, %s) ON CONFLICT DO NOTHING
                    """,
                    (incident_id, event_id),
                )
            self._insert_audit(
                cursor, action, None, incident_id,
                {"indicator_type": indicator_type, "indicator_value": indicator_value,
                 "risk_score": int(payload["risk_score"]), "event_count": len(payload["event_ids"])},
            )
        return payload

    def list_incidents(
        self, limit: int = 100, status: str | None = None
    ) -> list[dict[str, object]]:
        filters = "WHERE status = %s" if status else ""
        params = (status, limit) if status else (limit,)
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                f"SELECT payload FROM incidents {filters} "
                "ORDER BY risk_score DESC, last_seen_at DESC LIMIT %s",
                params,
            )
            rows = cursor.fetchall()
        return [row[0] for row in rows]

    def get_incident(self, incident_id: str) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT payload FROM incidents WHERE incident_id = %s", (incident_id,)
            )
            row = cursor.fetchone()
        return row[0] if row else None

    def get_incident_events(self, incident_id: str) -> list[EventEnvelope]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT e.payload FROM incident_events ie
                JOIN events e ON e.event_id = ie.event_id
                WHERE ie.incident_id = %s
                ORDER BY e.received_at ASC, e.event_id ASC
                """,
                (incident_id,),
            )
            rows = cursor.fetchall()
        return [EventEnvelope.model_validate(row[0]) for row in rows]

    def update_incident_status(
        self, incident_id: str, status: str, reason: str = ""
    ) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT payload FROM incidents WHERE incident_id = %s FOR UPDATE",
                (incident_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            payload = {**row[0], "status": status, "status_reason": reason}
            cursor.execute(
                """
                UPDATE incidents SET status = %s, payload = %s, updated_at = NOW()
                WHERE incident_id = %s
                """,
                (status, Jsonb(payload), incident_id),
            )
            self._insert_audit(
                cursor, "incident.status.updated", None, incident_id,
                {"status": status, "reason": reason[:200]},
            )
        return payload

    def set_integration_secret(self, integration_id: str, encrypted_value: bytes) -> None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO integration_secrets (integration_id, encrypted_value)
                VALUES (%s, %s)
                ON CONFLICT (integration_id) DO UPDATE
                SET encrypted_value = EXCLUDED.encrypted_value, updated_at = NOW()
                """,
                (integration_id, encrypted_value),
            )
            self._insert_audit(
                cursor, "integration.secret.updated", None, integration_id,
                {"encrypted": True},
            )

    def get_integration_secret(self, integration_id: str) -> bytes | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT encrypted_value FROM integration_secrets WHERE integration_id = %s",
                (integration_id,),
            )
            row = cursor.fetchone()
        return bytes(row[0]) if row else None

    def list_integration_secret_ids(self) -> list[str]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT integration_id FROM integration_secrets ORDER BY integration_id"
            )
            rows = cursor.fetchall()
        return [str(row[0]) for row in rows]

    def delete_integration_secret(self, integration_id: str) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM integration_secrets WHERE integration_id = %s RETURNING integration_id",
                (integration_id,),
            )
            deleted = cursor.fetchone() is not None
            if deleted:
                self._insert_audit(
                    cursor, "integration.secret.deleted", None, integration_id, {},
                )
            return deleted

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

    def update_integration(
        self, integration: Integration, actor_id: str | None = None
    ) -> Integration | None:
        payload = integration.model_dump(mode="json")
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE integrations SET payload = %s
                WHERE integration_id = %s
                RETURNING integration_id
                """,
                (Jsonb(payload), integration.integration_id),
            )
            if cursor.fetchone() is None:
                return None
            self._insert_audit(
                cursor, "integration.updated", actor_id, integration.integration_id,
                {"kind": integration.kind},
            )
        return integration

    def delete_integration(
        self, integration_id: str, actor_id: str | None = None
    ) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM integrations WHERE integration_id = %s RETURNING payload",
                (integration_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return False
            integration = Integration.model_validate(row[0])
            self._insert_audit(
                cursor, "integration.deleted", actor_id, integration_id,
                {"kind": integration.kind, "history_preserved": True},
            )
        return True

    def get_integration_poll_cursor(self, integration_id: str) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT cursor FROM integration_poll_cursors WHERE integration_id = %s",
                (integration_id,),
            )
            row = cursor.fetchone()
        return row[0] if row else None

    def delete_integration_poll_cursor(self, integration_id: str) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM integration_poll_cursors WHERE integration_id = %s RETURNING integration_id",
                (integration_id,),
            )
            return cursor.fetchone() is not None

    def set_integration_poll_cursor(
        self, integration_id: str, provider_kind: str, value: dict[str, object]
    ) -> None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO integration_poll_cursors (integration_id, provider_kind, cursor)
                VALUES (%s, %s, %s)
                ON CONFLICT (integration_id) DO UPDATE
                SET provider_kind = EXCLUDED.provider_kind,
                    cursor = EXCLUDED.cursor, updated_at = NOW()
                """,
                (integration_id, provider_kind, Jsonb(value)),
            )

    def checkpoint_integration_poll_page(
        self,
        integration_id: str,
        provider_kind: str,
        value: dict[str, object],
        completion_details: dict[str, object],
        rejection_details: dict[str, object] | None = None,
    ) -> None:
        """Atomically persist page diagnostics and advance its provider cursor."""
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO integration_poll_cursors (integration_id, provider_kind, cursor)
                VALUES (%s, %s, %s)
                ON CONFLICT (integration_id) DO UPDATE
                SET provider_kind = EXCLUDED.provider_kind,
                    cursor = EXCLUDED.cursor, updated_at = NOW()
                """,
                (integration_id, provider_kind, Jsonb(value)),
            )
            if rejection_details is not None:
                self._insert_audit(
                    cursor, "privacy.provider_poll.records_rejected", None,
                    integration_id, rejection_details,
                )
            self._insert_audit(
                cursor, "privacy.provider_poll.completed", None,
                integration_id, completion_details,
            )

    def insert_event(self, event: EventEnvelope, actor_id: str | None = None) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO events (event_id, payload, occurred_at)
                VALUES (%s, %s, %s)
                ON CONFLICT (event_id) DO NOTHING
                RETURNING event_id
                """,
                (
                    event.event_id,
                    Jsonb(event.model_dump(mode="json")),
                    event.occurred_at,
                ),
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

    def record_gateway_discovery(
        self, gateway_id: str, payload: dict[str, object], observed_at: datetime
    ) -> None:
        snapshot = {
            "board": payload.get("board", {}),
            "interfaces": payload.get("interfaces", []),
            "device_discovery": payload.get("device_discovery", {}),
        }
        devices = payload.get("devices", [])
        if not isinstance(devices, list):
            devices = []
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO gateway_discovery_snapshots (gateway_id, payload, observed_at)
                VALUES (%s, %s, %s)
                ON CONFLICT (gateway_id) DO UPDATE
                SET payload = CASE
                        WHEN EXCLUDED.observed_at >= gateway_discovery_snapshots.observed_at
                        THEN EXCLUDED.payload ELSE gateway_discovery_snapshots.payload END,
                    observed_at = GREATEST(
                        gateway_discovery_snapshots.observed_at, EXCLUDED.observed_at
                    )
                """,
                (gateway_id, Jsonb(snapshot), observed_at),
            )
            for device in devices:
                if not isinstance(device, dict):
                    continue
                mac = device.get("mac_address")
                if not isinstance(mac, str) or not re.fullmatch(
                    r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac
                ):
                    continue
                if not _has_valid_device_address(device):
                    continue
                normalized_mac = mac.lower()
                cursor.execute(
                    """
                    INSERT INTO network_devices (
                        gateway_id, mac_address, payload, first_seen_at, last_seen_at
                    ) VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (gateway_id, mac_address) DO UPDATE
                    SET payload = CASE
                            WHEN EXCLUDED.last_seen_at >= network_devices.last_seen_at
                            THEN EXCLUDED.payload ELSE network_devices.payload END,
                        last_seen_at = GREATEST(
                            network_devices.last_seen_at, EXCLUDED.last_seen_at
                        )
                    """,
                    (gateway_id, normalized_mac, Jsonb(device), observed_at, observed_at),
                )
                address_evidence = device.get("address_evidence")
                if not isinstance(address_evidence, dict):
                    address_evidence = {}
                    for field in ("ipv4_addresses", "ipv6_addresses"):
                        addresses = device.get(field, [])
                        if isinstance(addresses, list):
                            for address in addresses:
                                if isinstance(address, str):
                                    address_evidence.setdefault(address, []).append({
                                        "source": "luci_host_hints",
                                        "confidence": "medium",
                                    })
                for address, evidence_items in address_evidence.items():
                    if not isinstance(address, str) or not isinstance(evidence_items, list):
                        continue
                    try:
                        parsed_address = ipaddress.ip_address(address)
                    except ValueError:
                        continue
                    if (
                        parsed_address.is_unspecified
                        or parsed_address.is_multicast
                        or parsed_address.is_loopback
                    ):
                        continue
                    for evidence in evidence_items:
                        if not isinstance(evidence, dict):
                            continue
                        source = evidence.get("source")
                        confidence = evidence.get("confidence")
                        if source not in {"luci_host_hints", "dhcp_lease"}:
                            continue
                        expected_confidence = (
                            "high" if source == "dhcp_lease" else "medium"
                        )
                        if confidence != expected_confidence:
                            confidence = expected_confidence
                        cursor.execute(
                            """
                            INSERT INTO network_device_address_observations (
                                gateway_id, mac_address, ip_address, source, confidence,
                                first_seen_at, last_seen_at
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (gateway_id, mac_address, ip_address, source)
                            DO UPDATE SET
                                confidence = EXCLUDED.confidence,
                                last_seen_at = GREATEST(
                                    network_device_address_observations.last_seen_at,
                                    EXCLUDED.last_seen_at
                                )
                            """,
                            (
                                gateway_id, normalized_mac, str(parsed_address), source,
                                confidence, observed_at, observed_at,
                            ),
                        )

    def list_gateway_discovery_snapshots(self) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT gateway_id, payload, observed_at FROM gateway_discovery_snapshots "
                "ORDER BY observed_at DESC, gateway_id"
            )
            rows = cursor.fetchall()
        return [
            {"gateway_id": row[0], "payload": row[1], "observed_at": row[2]}
            for row in rows
        ]

    def list_gateway_devices(self, limit: int = 2000) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT gateway_id, mac_address, payload, first_seen_at, last_seen_at
                FROM network_devices
                ORDER BY last_seen_at DESC, gateway_id, mac_address
                LIMIT %s
                """,
                (limit,),
            )
            rows = cursor.fetchall()
        return [
            {
                "gateway_id": row[0], "mac_address": row[1], "payload": row[2],
                "first_seen_at": row[3], "last_seen_at": row[4],
            }
            for row in rows
        ]
    def list_device_identity_observations(
        self, limit: int = 10000
    ) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT gateway_id, mac_address, ip_address, source, confidence,
                       first_seen_at, last_seen_at
                FROM network_device_address_observations
                WHERE last_seen_at >= NOW() - INTERVAL '30 days'
                ORDER BY ip_address, last_seen_at DESC, gateway_id, mac_address, source
                LIMIT %s
                """,
                (limit,),
            )
            rows = cursor.fetchall()
        return [
            {
                "gateway_id": row[0],
                "mac_address": row[1],
                "ip_address": row[2],
                "source": row[3],
                "confidence": row[4],
                "first_seen_at": row[5],
                "last_seen_at": row[6],
            }
            for row in rows
        ]

    def list_events_page(self, integration_id=None, event_type=None, severity=None, limit=200, cursor=None):
        filters = []
        params = []
        if integration_id:
            filters.append("payload #>> '{source,integration_id}' = %s")
            params.append(integration_id)
        if event_type:
            filters.append("payload->>'event_type' = %s")
            params.append(event_type)
        if severity:
            filters.append("payload->>'severity' = %s")
            params.append(severity)
        if cursor:
            filters.append("(received_at, event_id) < (%s, %s)")
            params.extend(cursor)
        where = f"WHERE {' AND '.join(filters)}" if filters else ""
        params.append(limit + 1)
        with self._connect() as connection, connection.cursor() as db_cursor:
            db_cursor.execute(
                f"SELECT payload, received_at, event_id FROM events {where} "
                "ORDER BY received_at DESC, event_id DESC LIMIT %s", params
            )
            rows = db_cursor.fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        next_cursor = (rows[-1][1], rows[-1][2]) if has_more and rows else None
        return [EventEnvelope.model_validate(row[0]) for row in rows], next_cursor

    def purge_events_before(self, cutoff: datetime, batch_size: int = 1000) -> int:
        if not 1 <= batch_size <= 10000:
            raise ValueError("batch_size must be between 1 and 10000")
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """WITH doomed AS (
                    SELECT event_id FROM events WHERE received_at < %s
                    ORDER BY received_at, event_id LIMIT %s
                )
                DELETE FROM events e USING doomed d
                WHERE e.event_id = d.event_id RETURNING e.event_id""",
                (cutoff, batch_size),
            )
            return len(cursor.fetchall())

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
            SELECT last_audit_id, last_hash
            FROM audit_chain_state
            WHERE chain_id = 1
            FOR UPDATE
            """
        )
        head = cursor.fetchone()
        if head is None:
            raise StorageConfigurationError("Audit chain state is missing")
        last_audit_id, previous_hash = int(head[0]), str(head[1])

        cursor.execute(
            "SELECT nextval(pg_get_serial_sequence('audit_records', 'audit_id'))"
        )
        sequence_row = cursor.fetchone()
        if sequence_row is None:
            raise StorageConfigurationError("Audit record sequence is unavailable")
        audit_id = int(sequence_row[0])
        if audit_id <= last_audit_id:
            raise StorageConfigurationError("Audit record sequence is behind the chain head")

        occurred_at = datetime.now(UTC)
        record_hash = audit_record_hash(
            audit_id=audit_id,
            occurred_at=occurred_at,
            actor_id=actor_id,
            action=action,
            target_id=target_id,
            details=details,
            previous_hash=previous_hash,
        )
        cursor.execute(
            """
            INSERT INTO audit_records (
                audit_id, occurred_at, actor_id, action, target_id, details,
                previous_hash, record_hash
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                audit_id,
                occurred_at,
                actor_id,
                action,
                target_id,
                Jsonb(details),
                previous_hash,
                record_hash,
            ),
        )
        cursor.execute(
            """
            UPDATE audit_chain_state
            SET last_audit_id = %s, last_hash = %s
            WHERE chain_id = 1
            """,
            (audit_id, record_hash),
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
                SELECT audit_id, occurred_at, actor_id, action, target_id, details,
                       previous_hash, record_hash
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
                "previous_hash": row[6],
                "record_hash": row[7],
            }
            for row in rows
        ]


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
