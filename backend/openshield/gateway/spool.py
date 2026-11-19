import json
import os
import sqlite3
from cryptography.fernet import Fernet, InvalidToken
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from openshield.events.models import EventEnvelope


class SpoolFullError(RuntimeError):
    pass


class SpoolEncryptionError(RuntimeError):
    """The gateway spool cannot be decrypted with the configured key set."""


_ENCRYPTED_PAYLOAD_PREFIX = "fernet:v1:"


class GatewayEventSpool:
    """SQLite-backed durable outbox for events waiting to reach the Node."""

    def __init__(
        self,
        path: str,
        max_events: int = 10_000,
        *,
        encryption_key: str | None = None,
        previous_encryption_keys: str | None = None,
    ) -> None:
        if max_events < 1:
            raise ValueError("Spool capacity must be positive")
        self._path = Path(path)
        if not self._path.is_absolute():
            raise ValueError("Gateway spool path must be absolute")
        self._max_events = max_events
        try:
            self._cipher = Fernet(encryption_key.encode("ascii")) if encryption_key else None
            self._previous_ciphers = [
                Fernet(value.strip().encode("ascii"))
                for value in (previous_encryption_keys or "").split(",")
                if value.strip()
            ]
        except (ValueError, UnicodeEncodeError) as exc:
            raise SpoolEncryptionError("Gateway spool encryption key configuration is invalid") from exc
        self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self._path.parent, 0o700)
        with self._connection() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA secure_delete=ON")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS pending_events (
                    event_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS pending_events_created_at_idx "
                "ON pending_events (created_at, event_id)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS gateway_spool_counters (
                    name TEXT PRIMARY KEY,
                    value INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            connection.executemany(
                "INSERT OR IGNORE INTO gateway_spool_counters (name, value) VALUES (?, 0)",
                (
                    ("evicted_events",),
                    ("coalesced_health_events",),
                    ("dropped_events",),
                    ("pending_events",),
                ),
            )
            # Reconcile once at startup so restarts recover the transactional count.
            connection.execute(
                """
                UPDATE gateway_spool_counters
                SET value = (SELECT COUNT(*) FROM pending_events)
                WHERE name = 'pending_events'
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS gateway_command_results (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    command_id TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL,
                    result TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    acknowledged_at TEXT,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS pending_command_results_retry_idx "
                "ON gateway_command_results (acknowledged_at, next_attempt_at, sequence)"
            )
            connection.execute("BEGIN IMMEDIATE")
            migrated_payloads = self._migrate_payloads(connection)
        if migrated_payloads:
            self._compact_encrypted_database()

    def _secure_file_permissions(self) -> None:
        sidecars = (Path(f"{self._path}-wal"), Path(f"{self._path}-shm"))
        for path in (self._path, *sidecars):
            try:
                os.chmod(path, 0o600)
            except FileNotFoundError:
                pass

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self._path, timeout=5)
        try:
            connection.execute("PRAGMA synchronous=FULL")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
            self._secure_file_permissions()

    def _encode_payload(self, payload: str) -> str:
        if self._cipher is None:
            return payload
        token = self._cipher.encrypt(payload.encode("utf-8")).decode("ascii")
        return _ENCRYPTED_PAYLOAD_PREFIX + token

    def _decode_payload(self, stored: str) -> tuple[str, str, bool]:
        if not stored.startswith(_ENCRYPTED_PAYLOAD_PREFIX):
            if self._cipher is None:
                return stored, stored, False
            return stored, self._encode_payload(stored), True
        if self._cipher is None:
            raise SpoolEncryptionError(
                "Gateway spool is encrypted but OPENSHIELD_SECRET_KEY is not configured"
            )
        token = stored[len(_ENCRYPTED_PAYLOAD_PREFIX):].encode("ascii")
        for index, cipher in enumerate((self._cipher, *self._previous_ciphers)):
            try:
                plaintext = cipher.decrypt(token).decode("utf-8")
            except (InvalidToken, UnicodeDecodeError):
                continue
            if index == 0:
                return plaintext, stored, False
            return plaintext, self._encode_payload(plaintext), True
        raise SpoolEncryptionError(
            "Gateway spool data cannot be decrypted; verify OPENSHIELD_SECRET_KEY "
            "and OPENSHIELD_SECRET_KEY_PREVIOUS"
        )

    def _migrate_payloads(self, connection: sqlite3.Connection) -> bool:
        """Encrypt legacy plaintext rows and rotate payloads encrypted with old keys."""
        changed = False
        for table, column, key_column in (
            ("pending_events", "payload", "event_id"),
            ("gateway_command_results", "result", "command_id"),
        ):
            rows = connection.execute(
                f"SELECT {key_column}, {column} FROM {table}"
            ).fetchall()
            for row_key, stored in rows:
                _plaintext, replacement, migrated = self._decode_payload(str(stored))
                if migrated:
                    connection.execute(
                        f"UPDATE {table} SET {column} = ? WHERE {key_column} = ?",
                        (replacement, row_key),
                    )
                    changed = True
        return changed

    def _compact_encrypted_database(self) -> None:
        """Reclaim old plaintext pages after the one-time spool encryption migration."""
        connection = sqlite3.connect(self._path, timeout=30, isolation_level=None)
        try:
            connection.execute("PRAGMA secure_delete=ON")
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            connection.execute("VACUUM")
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            connection.close()
            self._secure_file_permissions()

    @staticmethod
    def _protected_event(payload: dict[str, object]) -> bool:
        event_type = str(payload.get("event_type", ""))
        severity = str(payload.get("severity", ""))
        return (
            event_type == "gateway.health"
            or event_type == "gateway.command_result"
            or event_type.startswith(("security.", "audit."))
            or severity in {"high", "critical"}
        )

    @staticmethod
    def _health_compaction_key(payload: dict[str, object]) -> tuple[str, str, str] | None:
        if payload.get("event_type") != "gateway.health":
            return None
        source = payload.get("source")
        health_payload = payload.get("payload")
        if not isinstance(source, dict) or not isinstance(health_payload, dict):
            return None
        integration_id = source.get("integration_id")
        if not isinstance(integration_id, str):
            return None
        # Only identical health snapshots may be compacted. State transitions remain durable.
        fingerprint = json.dumps(health_payload, sort_keys=True, separators=(",", ":"))
        return integration_id, str(payload.get("event_type")), fingerprint

    @staticmethod
    def _increment_counter(connection: sqlite3.Connection, name: str) -> None:
        connection.execute(
            "UPDATE gateway_spool_counters SET value = value + 1 WHERE name = ?",
            (name,),
        )

    @staticmethod
    def _adjust_pending_count(connection: sqlite3.Connection, delta: int) -> None:
        connection.execute(
            "UPDATE gateway_spool_counters SET value = value + ? WHERE name = 'pending_events'",
            (delta,),
        )

    def enqueue(self, event: EventEnvelope) -> bool:
        payload_dict = event.model_dump(mode="json")
        payload = self._encode_payload(json.dumps(payload_dict, separators=(",", ":")))
        created_at = datetime.now(UTC).isoformat()
        full = False
        with self._connection() as connection:
            # Serialize capacity checks with inserts/deletes across threads and processes.
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute(
                "SELECT 1 FROM pending_events WHERE event_id = ?",
                (event.event_id,),
            ).fetchone():
                return False

            count = int(connection.execute(
                "SELECT value FROM gateway_spool_counters WHERE name = 'pending_events'"
            ).fetchone()[0])
            if count >= self._max_events:
                rows = connection.execute(
                    "SELECT event_id, payload FROM pending_events ORDER BY created_at, event_id"
                ).fetchall()
                evict_id = next(
                    (
                        row[0] for row in rows
                        if not self._protected_event(json.loads(self._decode_payload(row[1])[0]))
                    ),
                    None,
                )
                if evict_id is not None:
                    connection.execute(
                        "DELETE FROM pending_events WHERE event_id = ?", (evict_id,)
                    )
                    self._increment_counter(connection, "evicted_events")
                    self._adjust_pending_count(connection, -1)
                else:
                    incoming_key = self._health_compaction_key(payload_dict)
                    compact_id = None
                    if incoming_key is not None:
                        for row in rows:
                            existing = json.loads(self._decode_payload(row[1])[0])
                            if self._health_compaction_key(existing) == incoming_key:
                                compact_id = row[0]
                                break
                    if compact_id is not None:
                        connection.execute(
                            "DELETE FROM pending_events WHERE event_id = ?", (compact_id,)
                        )
                        self._increment_counter(connection, "coalesced_health_events")
                        self._adjust_pending_count(connection, -1)
                    else:
                        self._increment_counter(connection, "dropped_events")
                        full = True

            if not full:
                connection.execute(
                    """
                    INSERT INTO pending_events (event_id, payload, created_at)
                    VALUES (?, ?, ?)
                    """,
                    (event.event_id, payload, created_at),
                )
                self._adjust_pending_count(connection, 1)
        if full:
            raise SpoolFullError(
                "Gateway event spool is full; protected events were retained"
            )
        return True

    def pending(self, limit: int = 100) -> list[EventEnvelope]:
        if not 1 <= limit <= 1000:
            raise ValueError("Spool read limit must be between 1 and 1000")
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT payload FROM pending_events
                ORDER BY created_at, event_id
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            EventEnvelope.model_validate(json.loads(self._decode_payload(row[0])[0]))
            for row in rows
        ]

    def acknowledge(self, event_id: str) -> None:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "DELETE FROM pending_events WHERE event_id = ?",
                (event_id,),
            )
            if cursor.rowcount:
                self._adjust_pending_count(connection, -1)

    def enqueue_command_result(
        self, command_id: str, status: str, result: dict[str, object],
    ) -> bool:
        payload = self._encode_payload(json.dumps(result, separators=(",", ":"), sort_keys=True))
        created_at = datetime.now(UTC).isoformat()
        with self._connection() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO gateway_command_results
                    (command_id, status, result, created_at, next_attempt_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (command_id, status, payload, created_at, created_at),
            )
            if cursor.rowcount == 0:
                row = connection.execute(
                    "SELECT status, result FROM gateway_command_results WHERE command_id = ?",
                    (command_id,),
                ).fetchone()
                if row != (status, payload):
                    raise ValueError("Gateway command result cannot be changed once persisted")
                return False
        return True

    def get_command_result(self, command_id: str) -> dict[str, object] | None:
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT command_id, status, result, acknowledged_at
                FROM gateway_command_results WHERE command_id = ?
                """,
                (command_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "command_id": row[0],
            "status": row[1],
            "result": json.loads(self._decode_payload(row[2])[0]),
            "acknowledged": row[3] is not None,
        }

    def pending_command_results(self, limit: int = 100) -> list[dict[str, object]]:
        if not 1 <= limit <= 1000:
            raise ValueError("Command result read limit must be between 1 and 1000")
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT command_id, status, result, next_attempt_at
                FROM gateway_command_results
                WHERE acknowledged_at IS NULL
                ORDER BY sequence
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        now = datetime.now(UTC).isoformat()
        pending = []
        for row in rows:
            if row[3] > now:
                break
            pending.append({
                "command_id": row[0],
                "status": row[1],
                "result": json.loads(self._decode_payload(row[2])[0]),
            })
        return pending

    def defer_command_result(self, command_id: str) -> None:
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT attempts FROM gateway_command_results
                WHERE command_id = ? AND acknowledged_at IS NULL
                """,
                (command_id,),
            ).fetchone()
            if row is None:
                return
            delay = min(2 ** min(int(row[0]), 6), 60)
            next_attempt = (datetime.now(UTC) + timedelta(seconds=delay)).isoformat()
            connection.execute(
                """
                UPDATE gateway_command_results
                SET attempts = attempts + 1, next_attempt_at = ?
                WHERE command_id = ? AND acknowledged_at IS NULL
                """,
                (next_attempt, command_id),
            )

    def acknowledge_command_result(self, command_id: str) -> None:
        with self._connection() as connection:
            connection.execute(
                """
                UPDATE gateway_command_results SET acknowledged_at = ?
                WHERE command_id = ? AND acknowledged_at IS NULL
                """,
                (datetime.now(UTC).isoformat(), command_id),
            )

    def pending_count(self) -> int:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT COUNT(*) FROM pending_events"
            ).fetchone()
        return int(row[0])

    def stats(self) -> dict[str, int]:
        """Return durable retention counters and current queue depth."""
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT name, value FROM gateway_spool_counters"
            ).fetchall()
            pending = connection.execute(
                "SELECT COUNT(*) FROM pending_events"
            ).fetchone()[0]
        result = {str(name): int(value) for name, value in rows}
        result["pending_events"] = int(pending)
        result["capacity"] = self._max_events
        return result
