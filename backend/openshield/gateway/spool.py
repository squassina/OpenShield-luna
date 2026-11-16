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
                CREATE TABLE IF NOT EXISTS gateway_command_results (
                    command_id TEXT PRIMARY KEY,
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
                "CREATE INDEX IF NOT EXISTS pending_command_results_created_at_idx "
                "ON gateway_command_results (acknowledged_at, next_attempt_at, created_at)"
            )
        os.chmod(self._path, 0o600)

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

    def enqueue(self, event: EventEnvelope) -> bool:
        payload = json.dumps(event.model_dump(mode="json"), separators=(",", ":"))
        with self._connection() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO pending_events (event_id, payload, created_at)
                VALUES (?, ?, ?)
                """,
                (event.event_id, payload, datetime.now(UTC).isoformat()),
            )
            if cursor.rowcount == 0:
                return False
            count = connection.execute(
                "SELECT COUNT(*) FROM pending_events"
            ).fetchone()[0]
            if count > self._max_events:
                raise SpoolFullError("Gateway event spool is full")
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
                SELECT command_id, status, result
                FROM gateway_command_results
                WHERE acknowledged_at IS NULL AND next_attempt_at <= ?
                ORDER BY rowid
                LIMIT ?
                """,
                (datetime.now(UTC).isoformat(), limit),
            ).fetchall()
        return [
            {"command_id": row[0], "status": row[1], "result": json.loads(row[2])}
            for row in rows
        ]

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
