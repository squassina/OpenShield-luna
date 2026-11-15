from __future__ import annotations

from typing import Any, Self

import pytest

from openshield.core import storage


class FakeDatabase:
    def __init__(self) -> None:
        self.version = 0
        self.applied_statements: list[str] = []
        self.fail_on: str | None = None


class FakeCursor:
    def __init__(self, database: FakeDatabase) -> None:
        self.database = database
        self.row: tuple[int] | None = None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def execute(self, statement: str, params: tuple[Any, ...] | None = None) -> None:
        normalized = " ".join(statement.split())
        if normalized.startswith("SELECT COALESCE(MAX(version)"):
            self.row = (self.database.version,)
            return
        if normalized.startswith("INSERT INTO schema_migrations"):
            assert params is not None
            self.database.version = int(params[0])
            return
        if self.database.fail_on and self.database.fail_on in normalized:
            raise RuntimeError("simulated migration failure")
        self.database.applied_statements.append(normalized)

    def fetchone(self) -> tuple[int] | None:
        return self.row


class FakeConnection:
    def __init__(self, database: FakeDatabase) -> None:
        self.database = database
        self.version_before = database.version
        self.statements_before = len(database.applied_statements)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: object, *_: object) -> None:
        if exc_type is not None:
            self.database.version = self.version_before
            del self.database.applied_statements[self.statements_before:]

    def cursor(self) -> FakeCursor:
        return FakeCursor(self.database)


def install_fake_database(monkeypatch: pytest.MonkeyPatch, database: FakeDatabase) -> None:
    monkeypatch.setattr(
        storage.psycopg,
        "connect",
        lambda *_args, **_kwargs: FakeConnection(database),
    )


def test_initial_schema_is_recorded_and_not_reapplied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = FakeDatabase()
    install_fake_database(monkeypatch, database)
    store = storage.PostgresStore("postgresql://test")

    store.ensure_schema()
    statement_count = len(database.applied_statements)
    store._schema_ready = False
    store.ensure_schema()

    assert database.version == 1
    assert statement_count > 1
    assert len(database.applied_statements) == statement_count
    assert "SELECT pg_advisory_xact_lock(731946205)" in database.applied_statements


def test_failed_migration_does_not_record_version_or_mark_schema_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = FakeDatabase()
    database.fail_on = "CREATE TABLE IF NOT EXISTS integrations"
    install_fake_database(monkeypatch, database)
    store = storage.PostgresStore("postgresql://test")

    with pytest.raises(RuntimeError, match="simulated migration failure"):
        store.ensure_schema()

    assert database.version == 0
    assert store._schema_ready is False

    database.fail_on = None
    store.ensure_schema()
    assert database.version == 1
    assert store._schema_ready is True


def test_legacy_database_without_migration_history_runs_baseline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = FakeDatabase()
    install_fake_database(monkeypatch, database)
    store = storage.PostgresStore("postgresql://test")

    store.ensure_schema()

    assert database.version == 1
    assert any(
        "CREATE TABLE IF NOT EXISTS integrations" in item
        for item in database.applied_statements
    )


def test_database_newer_than_application_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = FakeDatabase()
    database.version = 2
    install_fake_database(monkeypatch, database)
    store = storage.PostgresStore("postgresql://test")

    with pytest.raises(
        storage.StorageConfigurationError,
        match="newer than this application",
    ):
        store.ensure_schema()

    assert store._schema_ready is False
