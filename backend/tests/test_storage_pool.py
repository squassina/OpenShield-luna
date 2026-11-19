import asyncio
import os
from typing import Self

import pytest

from openshield.core.storage import (
    AdvisoryLockUnavailable,
    PostgresStore,
    StorageConfigurationError,
)


@pytest.fixture
def database_url() -> str:
    value = os.getenv("OPENSHIELD_DATABASE_URL", "").strip()
    if not value:
        pytest.skip("OPENSHIELD_DATABASE_URL is not configured")
    return value


def test_pool_reuses_physical_connections_and_closes(database_url: str) -> None:
    store = PostgresStore(
        database_url,
        pool_min_size=1,
        pool_max_size=1,
        pool_timeout=1,
    )
    try:
        store.open()
        with store._connect() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT pg_backend_pid()")
            first_pid = cursor.fetchone()[0]
        with store._connect() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT pg_backend_pid()")
            second_pid = cursor.fetchone()[0]

        assert first_pid == second_pid
        pool = store._pool
        assert pool is not None
    finally:
        store.close()

    assert pool.closed


def test_pool_exhaustion_is_bounded_and_reports_not_ready(database_url: str) -> None:
    store = PostgresStore(
        database_url,
        pool_min_size=1,
        pool_max_size=1,
        pool_timeout=1,
    )
    try:
        store.open()
        with store._connect():
            assert store.is_ready() is False
        assert store.is_ready() is True
    finally:
        store.close()


def test_closed_pool_reopens_for_non_asgi_store_usage(database_url: str) -> None:
    store = PostgresStore(database_url, pool_min_size=1, pool_max_size=1)
    try:
        store.open()
        first_pool = store._pool
        store.close()
        assert first_pool is not None and first_pool.closed

        with store._connect() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            assert cursor.fetchone() == (1,)
        assert store._pool is not first_pool
    finally:
        store.close()


def test_pool_configuration_is_bounded() -> None:
    with pytest.raises(StorageConfigurationError, match="pool sizes"):
        PostgresStore("postgresql://test", pool_min_size=2, pool_max_size=1)
    with pytest.raises(StorageConfigurationError, match="pool timeout"):
        PostgresStore("postgresql://test", pool_timeout=31)


def test_advisory_lock_uses_a_dedicated_session_and_releases_on_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from openshield.core import storage

    calls: list[object] = []

    class FakeCursor:
        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def execute(self, query: str, params: tuple[int]) -> None:
            calls.append((query, params))

        def fetchone(self) -> tuple[bool]:
            return (True,)

    class FakeConnection:
        def cursor(self) -> FakeCursor:
            return FakeCursor()

        def commit(self) -> None:
            calls.append("commit")

        def close(self) -> None:
            calls.append("close")

    connection = FakeConnection()
    monkeypatch.setattr(
        storage.psycopg,
        "connect",
        lambda _dsn, connect_timeout: connection,
    )
    store = PostgresStore("postgresql://test")

    with store.advisory_lock(42):
        calls.append("inside")

    assert calls == [
        ("SELECT pg_try_advisory_lock(%s)", (42,)),
        "commit",
        "inside",
        ("SELECT pg_advisory_unlock(%s)", (42,)),
        "commit",
        "close",
    ]


def test_advisory_lock_rejects_a_second_process(monkeypatch: pytest.MonkeyPatch) -> None:
    from openshield.core import storage

    calls: list[str] = []

    class FakeCursor:
        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def execute(self, _query: str, _params: tuple[int]) -> None:
            return None

        def fetchone(self) -> tuple[bool]:
            return (False,)

    class FakeConnection:
        def cursor(self) -> FakeCursor:
            return FakeCursor()

        def commit(self) -> None:
            calls.append("commit")

        def close(self) -> None:
            calls.append("close")

    connection = FakeConnection()
    monkeypatch.setattr(
        storage.psycopg,
        "connect",
        lambda _dsn, connect_timeout: connection,
    )
    store = PostgresStore("postgresql://test")

    with pytest.raises(AdvisoryLockUnavailable, match="already holds"):
        with store.advisory_lock(42):
            pytest.fail("A competing process must not acquire the lock")

    assert calls == ["commit", "close"]


def test_postgres_advisory_lock_is_exclusive_across_connections(
    database_url: str,
) -> None:
    lock_id = 0x4F53484C54455354
    first = PostgresStore(database_url)
    second = PostgresStore(database_url)

    with first.advisory_lock(lock_id):
        with pytest.raises(AdvisoryLockUnavailable):
            with second.advisory_lock(lock_id):
                pytest.fail("A second PostgreSQL session must not acquire the lock")

    with second.advisory_lock(lock_id):
        pass


def test_application_lifespan_holds_process_lock_until_shutdown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from contextlib import contextmanager

    from openshield.api import main

    calls: list[str] = []
    monkeypatch.setenv("OPENSHIELD_DNS_POLL_INTERVAL_SECONDS", "0")
    monkeypatch.setattr(main.store, "open", lambda: calls.append("open"))
    monkeypatch.setattr(main.store, "close", lambda: calls.append("close"))

    @contextmanager
    def process_lock(lock_id: int):
        assert lock_id == main._NODE_PROCESS_LOCK_ID
        calls.append("lock")
        try:
            yield
        finally:
            calls.append("unlock")

    monkeypatch.setattr(main.store, "advisory_lock", process_lock)

    async def wait_for_shutdown(*_args: object) -> None:
        await asyncio.Event().wait()

    monkeypatch.setattr(main, "run_expiration_loop", wait_for_shutdown)

    async def exercise_lifespan() -> None:
        async with main._dns_polling_lifespan(main.app):
            assert calls == ["open", "lock"]

    asyncio.run(exercise_lifespan())
    assert calls == ["open", "lock", "unlock", "close"]


def test_application_lifespan_fails_if_another_node_process_is_active(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from contextlib import contextmanager

    from openshield.api import main

    calls: list[str] = []
    monkeypatch.setenv("OPENSHIELD_DNS_POLL_INTERVAL_SECONDS", "0")
    monkeypatch.setattr(main.store, "open", lambda: calls.append("open"))
    monkeypatch.setattr(main.store, "close", lambda: calls.append("close"))

    @contextmanager
    def busy_lock(_lock_id: int):
        raise AdvisoryLockUnavailable("already held")
        yield

    monkeypatch.setattr(main.store, "advisory_lock", busy_lock)

    async def exercise_lifespan() -> None:
        with pytest.raises(RuntimeError, match="exactly one Node API process"):
            async with main._dns_polling_lifespan(main.app):
                pytest.fail("The API must not start without the process lock")

    asyncio.run(exercise_lifespan())
    assert calls == ["open", "close"]


def test_response_execution_listing_uses_one_query_and_preserves_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from contextlib import contextmanager
    from datetime import UTC, datetime

    store = PostgresStore("postgresql://test")
    created_at = datetime(2026, 1, 1, tzinfo=UTC)
    expires_at = datetime(2026, 1, 2, tzinfo=UTC)
    rows = [
        (
            f"execution-{index}", "decision", "incident", "policy", "integration",
            "block_ip", "ip", f"192.0.2.{index}", "destination", "active", 600,
            expires_at, {"verified": True}, created_at, None,
        )
        for index in (1, 2)
    ]
    executed: list[tuple[str, tuple[object, ...]]] = []

    class FakeCursor:
        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def execute(self, query: str, params: tuple[object, ...] = ()) -> None:
            executed.append((query, params))

        def fetchall(self) -> list[tuple[object, ...]]:
            return rows

        def fetchone(self) -> None:
            return None

    class FakeConnection:
        def cursor(self) -> FakeCursor:
            return FakeCursor()

    @contextmanager
    def fake_connect():
        yield FakeConnection()

    monkeypatch.setattr(store, "_connect", fake_connect)
    monkeypatch.setattr(
        store,
        "get_response_execution",
        lambda _execution_id: (_ for _ in ()).throw(AssertionError("N+1 lookup")),
    )

    listed = store.list_response_executions(limit=25)
    assert len(executed) == 1
    assert "ORDER BY created_at DESC LIMIT %s" in executed[0][0]
    assert executed[0][1] == (25,)
    assert [item["execution_id"] for item in listed] == ["execution-1", "execution-2"]
    assert listed[0]["expires_at"] == expires_at.isoformat()
    assert listed[0]["created_at"] == created_at.isoformat()
    assert listed[0]["adapter_result"] == {"verified": True}

    executed.clear()
    due = store.get_due_response_executions()
    assert len(executed) == 1
    assert "ORDER BY expires_at ASC LIMIT 50" in executed[0][0]
    assert len(due) == 2
    assert due[1]["execution_id"] == "execution-2"

    rows.clear()
    executed.clear()
    assert store.list_response_executions() == []
    assert len(executed) == 1
    executed.clear()
    assert store.get_due_response_executions() == []
    assert len(executed) == 1
