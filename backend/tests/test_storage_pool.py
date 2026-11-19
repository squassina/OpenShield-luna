import asyncio
import os
from typing import Self

import pytest

from openshield.core.storage import PostgresStore, StorageConfigurationError


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


def test_background_worker_advisory_lock_is_exclusive_and_released(database_url: str) -> None:
    first = PostgresStore(database_url)
    second = PostgresStore(database_url)
    first_connection = second_connection = None
    try:
        first_connection = first.try_acquire_advisory_lock("test:singleton-worker")
        assert first_connection is not None
        assert second.try_acquire_advisory_lock("test:singleton-worker") is None
        first_connection.close()
        first_connection = None
        second_connection = second.try_acquire_advisory_lock("test:singleton-worker")
        assert second_connection is not None
    finally:
        if first_connection is not None:
            first_connection.close()
        if second_connection is not None:
            second_connection.close()
        first.close()
        second.close()


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


def test_application_lifespan_opens_and_closes_pool(monkeypatch: pytest.MonkeyPatch) -> None:
    from openshield.api import main

    calls: list[str] = []
    worker_started = asyncio.Event()

    class LockConnection:
        def close(self) -> None:
            calls.append("lock_close")

    monkeypatch.setenv("OPENSHIELD_DNS_POLL_INTERVAL_SECONDS", "0")
    monkeypatch.setattr(main.store, "open", lambda: calls.append("open"))
    monkeypatch.setattr(main.store, "close", lambda: calls.append("close"))
    monkeypatch.setattr(
        main.store,
        "try_acquire_advisory_lock",
        lambda _name: (calls.append("lease_acquired"), LockConnection())[1],
    )

    async def wait_for_shutdown(*_args: object) -> None:
        calls.append("worker_started")
        worker_started.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(main, "run_expiration_loop", wait_for_shutdown)

    async def exercise_lifespan() -> None:
        async with main._dns_polling_lifespan(main.app):
            await asyncio.wait_for(worker_started.wait(), timeout=2)
            assert calls[:3] == ["open", "lease_acquired", "worker_started"]

    asyncio.run(exercise_lifespan())
    assert calls[-2:] == ["lock_close", "close"]


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
