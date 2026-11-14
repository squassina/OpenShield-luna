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
                CREATE TABLE IF NOT EXISTS response_policies (
                    policy_id TEXT PRIMARY KEY,
                    payload JSONB NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS response_actions (
                    action_id TEXT PRIMARY KEY,
                    policy_id TEXT NOT NULL,
                    incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
                    status TEXT NOT NULL CHECK (status IN (
                        'pending_approval', 'approved', 'active', 'already_enforced',
                        'failed', 'rollback_pending', 'rolled_back', 'rejected',
                        'cancelled_by_kill_switch', 'blocked_by_kill_switch'
                    )),
                    payload JSONB NOT NULL,
                    expires_at TIMESTAMPTZ,
                    next_attempt_at TIMESTAMPTZ,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    UNIQUE (policy_id, incident_id)
                )
                """,
                """
                CREATE INDEX IF NOT EXISTS response_actions_expiry_idx
                ON response_actions (status, expires_at, next_attempt_at)
                """,
                """
                CREATE TABLE IF NOT EXISTS response_control (
                    control_id SMALLINT PRIMARY KEY CHECK (control_id = 1),
                    kill_switch_enabled BOOLEAN NOT NULL DEFAULT FALSE,
                    reason TEXT NOT NULL DEFAULT '',
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """,
                """
                INSERT INTO response_control (control_id, kill_switch_enabled)
                VALUES (1, FALSE) ON CONFLICT (control_id) DO NOTHING
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
                "TRUNCATE TABLE audit_records, response_actions, response_policies, response_control, integration_poll_cursors, privacy_classification_overrides, incident_investigations, incident_events, incidents, threat_intel_cache, integration_secrets, events, privacy_lists, gateway_connections, integrations RESTART IDENTITY"
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

    def create_response_policy(self, policy: dict[str, object]) -> None:
        policy_id = str(policy["policy_id"])
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO response_policies (policy_id, payload)
                VALUES (%s, %s) ON CONFLICT (policy_id) DO NOTHING
                RETURNING policy_id
                """,
                (policy_id, Jsonb(policy)),
            )
            if cursor.fetchone() is None:
                raise ValueError("Response policy already exists")
            self._insert_audit(
                cursor, "response.policy.created", None, policy_id,
                {"action_type": policy.get("action_type"), "provider_integration_id": policy.get("provider_integration_id")},
            )

    def get_response_policy(self, policy_id: str) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT payload FROM response_policies WHERE policy_id = %s", (policy_id,))
            row = cursor.fetchone()
        return row[0] if row else None

    def list_response_policies(self) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT payload FROM response_policies ORDER BY created_at, policy_id")
            rows = cursor.fetchall()
        return [row[0] for row in rows]

    def update_response_policy(self, policy: dict[str, object]) -> dict[str, object] | None:
        policy_id = str(policy["policy_id"])
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE response_policies SET payload = %s, updated_at = NOW()
                WHERE policy_id = %s RETURNING policy_id
                """,
                (Jsonb(policy), policy_id),
            )
            if cursor.fetchone() is None:
                return None
            self._insert_audit(
                cursor, "response.policy.updated", None, policy_id,
                {"enabled": policy.get("enabled"), "action_type": policy.get("action_type")},
            )
        return policy

    def delete_response_policy(self, policy_id: str) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM response_policies WHERE policy_id = %s RETURNING policy_id",
                (policy_id,),
            )
            deleted = cursor.fetchone() is not None
            if deleted:
                self._insert_audit(cursor, "response.policy.deleted", None, policy_id, {})
            return deleted

    def create_response_action(self, action: dict[str, object]) -> tuple[dict[str, object], bool]:
        action_id = str(action["action_id"])
        policy_id = str(action["policy_id"])
        incident_id = str(action["incident_id"])
        status = str(action["status"])
        expires_at = action.get("expires_at")
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO response_actions (action_id, policy_id, incident_id, status, payload, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (policy_id, incident_id) DO NOTHING
                RETURNING payload
                """,
                (action_id, policy_id, incident_id, status, Jsonb(action), expires_at),
            )
            row = cursor.fetchone()
            if row is None:
                cursor.execute(
                    "SELECT payload FROM response_actions WHERE policy_id = %s AND incident_id = %s",
                    (policy_id, incident_id),
                )
                existing = cursor.fetchone()
                return existing[0], False
            self._insert_audit(
                cursor, "response.action.created", None, action_id,
                {"policy_id": policy_id, "incident_id": incident_id, "status": status, "action_type": action.get("action_type")},
            )
        return row[0], True

    def get_response_action(self, action_id: str) -> dict[str, object] | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT payload FROM response_actions WHERE action_id = %s", (action_id,))
            row = cursor.fetchone()
        return row[0] if row else None

    def list_response_actions(self, limit: int = 100, status: str | None = None) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            if status:
                cursor.execute(
                    "SELECT payload FROM response_actions WHERE status = %s ORDER BY created_at DESC LIMIT %s",
                    (status, limit),
                )
            else:
                cursor.execute(
                    "SELECT payload FROM response_actions ORDER BY created_at DESC LIMIT %s",
                    (limit,),
                )
            rows = cursor.fetchall()
        return [row[0] for row in rows]

    def list_active_response_actions(self) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT payload FROM response_actions WHERE status IN ('active', 'rollback_pending') ORDER BY created_at"
            )
            rows = cursor.fetchall()
        return [row[0] for row in rows]

    def list_due_response_actions(self) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT payload FROM response_actions
                WHERE status IN ('active', 'rollback_pending')
                  AND expires_at <= NOW()
                  AND (next_attempt_at IS NULL OR next_attempt_at <= NOW())
                ORDER BY expires_at LIMIT 100
                """
            )
            rows = cursor.fetchall()
        return [row[0] for row in rows]

    def update_response_action(
        self, action_id: str, payload: dict[str, object], *,
        expires_at=None, next_attempt_at=None, attempts: int | None = None,
    ) -> dict[str, object] | None:
        status = str(payload["status"])
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT payload FROM response_actions WHERE action_id = %s FOR UPDATE",
                (action_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            merged = {**row[0], **payload}
            cursor.execute(
                """
                UPDATE response_actions
                SET status = %s, payload = %s, expires_at = %s,
                    next_attempt_at = %s,
                    attempts = COALESCE(%s, attempts),
                    updated_at = NOW()
                WHERE action_id = %s
                """,
                (status, Jsonb(merged), expires_at, next_attempt_at, attempts, action_id),
            )
            self._insert_audit(
                cursor, f"response.action.{status}", None, action_id,
                {"policy_id": merged.get("policy_id"), "action_type": merged.get("action_type"),
                 "attempts": attempts if attempts is not None else 0},
            )
        return merged

    def get_response_control(self) -> dict[str, object]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT kill_switch_enabled, reason, updated_at FROM response_control WHERE control_id = 1"
            )
            row = cursor.fetchone()
        if row is None:
            return {"kill_switch_enabled": False, "reason": "", "updated_at": None}
        return {
            "kill_switch_enabled": row[0], "reason": row[1],
            "updated_at": row[2].isoformat(),
        }

    def set_response_control(self, enabled: bool, reason: str = "") -> dict[str, object]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO response_control (control_id, kill_switch_enabled, reason)
                VALUES (1, %s, %s)
                ON CONFLICT (control_id) DO UPDATE
                SET kill_switch_enabled = EXCLUDED.kill_switch_enabled,
                    reason = EXCLUDED.reason, updated_at = NOW()
                RETURNING updated_at
                """,
                (enabled, reason[:500]),
            )
            updated_at = cursor.fetchone()[0]
            self._insert_audit(
                cursor, "response.kill_switch.updated", None, "global",
                {"enabled": enabled, "reason": reason[:200]},
            )
        return {"kill_switch_enabled": enabled, "reason": reason[:500], "updated_at": updated_at.isoformat()}

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
