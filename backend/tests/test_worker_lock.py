import asyncio

import pytest

from openshield.core import worker_lock


class FakeCursor:
    def __init__(self, acquired: bool) -> None:
        self.acquired = acquired

    async def fetchone(self) -> tuple[bool]:
        return (self.acquired,)


class FakeConnection:
    def __init__(self, acquired: bool) -> None:
        self.cursor = FakeCursor(acquired)
        self.closed = False
        self.statements: list[tuple[str, tuple[object, ...]]] = []

    async def execute(self, statement: str, parameters: tuple[object, ...] = ()) -> FakeCursor:
        self.statements.append((statement, parameters))
        return self.cursor

    async def close(self) -> None:
        self.closed = True


def test_worker_lock_returns_connection_when_lock_is_acquired(monkeypatch) -> None:
    connection = FakeConnection(True)

    async def connect(*_args, **_kwargs):
        return connection

    monkeypatch.setattr(worker_lock.psycopg.AsyncConnection, "connect", connect)
    result = asyncio.run(
        worker_lock._acquire_background_worker_lock("postgresql://db/test")
    )

    assert result is connection
    assert not connection.closed
    assert connection.statements[0][0] == "SELECT pg_try_advisory_lock(%s)"


def test_worker_lock_closes_connection_when_another_node_owns_lock(monkeypatch) -> None:
    connection = FakeConnection(False)

    async def connect(*_args, **_kwargs):
        return connection

    monkeypatch.setattr(worker_lock.psycopg.AsyncConnection, "connect", connect)
    result = asyncio.run(
        worker_lock._acquire_background_worker_lock("postgresql://db/test")
    )

    assert result is None
    assert connection.closed


def test_worker_lock_requires_a_database_dsn() -> None:
    with pytest.raises(ValueError, match="DATABASE_URL"):
        asyncio.run(worker_lock._acquire_background_worker_lock(" "))
