import json
import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
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
        os.chmod(self._path, 0o600)

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self._path, timeout=5)
        try:
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

    def pending_count(self) -> int:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT COUNT(*) FROM pending_events"
            ).fetchone()
        return int(row[0])
