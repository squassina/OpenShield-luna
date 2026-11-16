import json
import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from openshield.events.models import EventEnvelope


class SpoolFullError(RuntimeError):
    pass


class GatewayEventSpool:
    """SQLite-backed durable outbox for events waiting to reach the Node."""

    def __init__(self, path: str, max_events: int = 10_000) -> None:
        if max_events < 1:
            raise ValueError("Spool capacity must be positive")
        self._path = Path(path)
        if not self._path.is_absolute():
            raise ValueError("Gateway spool path must be absolute")
        self._max_events = max_events
        self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self._path.parent, 0o700)
        with self._connection() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
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
                (("evicted_events",), ("coalesced_health_events",), ("dropped_events",)),
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
    def _secure_file_permissions(self) -> None:
        for path in (self._path, Path(f"{self._path}-wal"), Path(f"{self._path}-shm")):
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

    def enqueue(self, event: EventEnvelope) -> bool:
        payload_dict = event.model_dump(mode="json")
        payload = json.dumps(payload_dict, separators=(",", ":"))
        created_at = datetime.now(UTC).isoformat()
        full = False
        with self._connection() as connection:
            if connection.execute(
                "SELECT 1 FROM pending_events WHERE event_id = ?",
                (event.event_id,),
            ).fetchone():
                return False

            count = int(connection.execute(
                "SELECT COUNT(*) FROM pending_events"
            ).fetchone()[0])
            if count >= self._max_events:
                rows = connection.execute(
                    "SELECT event_id, payload FROM pending_events ORDER BY created_at, event_id"
                ).fetchall()
                evict_id = next(
                    (
                        row[0] for row in rows
                        if not self._protected_event(json.loads(row[1]))
                    ),
                    None,
                )
                if evict_id is not None:
                    connection.execute(
                        "DELETE FROM pending_events WHERE event_id = ?", (evict_id,)
                    )
                    self._increment_counter(connection, "evicted_events")
                else:
                    incoming_key = self._health_compaction_key(payload_dict)
                    compact_id = None
                    if incoming_key is not None:
                        for row in rows:
                            existing = json.loads(row[1])
                            if self._health_compaction_key(existing) == incoming_key:
                                compact_id = row[0]
                                break
                    if compact_id is not None:
                        connection.execute(
                            "DELETE FROM pending_events WHERE event_id = ?", (compact_id,)
                        )
                        self._increment_counter(connection, "coalesced_health_events")
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
            EventEnvelope.model_validate(json.loads(row[0]))
            for row in rows
        ]

    def acknowledge(self, event_id: str) -> None:
        with self._connection() as connection:
            connection.execute(
                "DELETE FROM pending_events WHERE event_id = ?",
                (event_id,),
            )

    def enqueue_command_result(
        self, command_id: str, status: str, result: dict[str, object],
    ) -> bool:
        payload = json.dumps(result, separators=(",", ":"), sort_keys=True)
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
            "result": json.loads(row[2]),
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
                "result": json.loads(row[2]),
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
