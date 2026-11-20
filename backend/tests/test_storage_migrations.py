from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Self

import pytest

from openshield.core import storage
from openshield.core.audit_integrity import GENESIS_AUDIT_HASH, audit_record_hash


class FakeDatabase:
    def __init__(self) -> None:
        self.version = 0
        self.applied_statements: list[str] = []
        self.fail_on: str | None = None
        self.audit_rows: list[dict[str, object]] = []
        self.audit_chain_head: tuple[int, str] | None = None


class FakeCursor:
    def __init__(self, database: FakeDatabase) -> None:
        self.database = database
        self.row: tuple[object, ...] | None = None
        self.rows: list[tuple[object, ...]] = []

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
        if normalized.startswith("INSERT INTO audit_chain_state"):
            if self.database.audit_chain_head is None:
                assert params is not None
                self.database.audit_chain_head = (0, str(params[0]))
            return
        if normalized.startswith("SELECT last_audit_id, last_hash FROM audit_chain_state"):
            self.row = self.database.audit_chain_head
            return
        if normalized.startswith("SELECT audit_id, occurred_at, actor_id, action, target_id, details,"):
            assert params is not None
            after_id = int(params[0])
            selected = sorted(
                (
                    item for item in self.database.audit_rows
                    if int(item["audit_id"]) > after_id
                ),
                key=lambda item: int(item["audit_id"]),
            )[:500]
            self.rows = [
                (
                    item["audit_id"], item["occurred_at"], item["actor_id"],
                    item["action"], item["target_id"], item["details"],
                    item["previous_hash"], item["record_hash"],
                )
                for item in selected
            ]
            return
        if normalized.startswith("UPDATE audit_records SET previous_hash"):
            assert params is not None
            previous_hash, record_hash, audit_id = params
            for item in self.database.audit_rows:
                if int(item["audit_id"]) == int(audit_id):
                    item["previous_hash"] = previous_hash
                    item["record_hash"] = record_hash
                    break
            else:
                raise AssertionError(f"Unknown fake audit row {audit_id}")
            return
        if normalized.startswith("UPDATE audit_chain_state SET last_audit_id"):
            assert params is not None
            self.database.audit_chain_head = (int(params[0]), str(params[1]))
            return
        if self.database.fail_on and self.database.fail_on in normalized:
            raise RuntimeError("simulated migration failure")
        self.database.applied_statements.append(normalized)

    def fetchone(self) -> tuple[object, ...] | None:
        return self.row

    def fetchall(self) -> list[tuple[object, ...]]:
        return self.rows


class FakeConnection:
    def __init__(self, database: FakeDatabase) -> None:
        self.database = database
        self.version_before = database.version
        self.statements_before = len(database.applied_statements)
        self.audit_rows_before = [dict(item) for item in database.audit_rows]
        self.audit_chain_head_before = database.audit_chain_head

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: object, *_: object) -> None:
        if exc_type is not None:
            self.database.version = self.version_before
            del self.database.applied_statements[self.statements_before:]
            self.database.audit_rows = self.audit_rows_before
            self.database.audit_chain_head = self.audit_chain_head_before

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
    migration_statements = [
        statement
        for statement in database.applied_statements
        if not statement.startswith("SELECT pg_advisory_xact_lock")
        and not statement.startswith("CREATE TABLE IF NOT EXISTS schema_migrations")
    ]
    store._schema_ready = False
    store.ensure_schema()

    assert database.version == 4
    assert migration_statements
    assert [
        statement
        for statement in database.applied_statements
        if not statement.startswith("SELECT pg_advisory_xact_lock")
        and not statement.startswith("CREATE TABLE IF NOT EXISTS schema_migrations")
    ] == migration_statements
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
    assert database.version == 4
    assert store._schema_ready is True


def test_legacy_database_without_migration_history_runs_baseline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = FakeDatabase()
    install_fake_database(monkeypatch, database)
    store = storage.PostgresStore("postgresql://test")

    store.ensure_schema()

    assert database.version == 4
    assert any(
        "CREATE TABLE IF NOT EXISTS integrations" in item
        for item in database.applied_statements
    )


def test_upgrade_from_v1_backfills_typed_event_timestamps_and_indexes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = FakeDatabase()
    database.version = 1
    install_fake_database(monkeypatch, database)
    store = storage.PostgresStore("postgresql://test")

    store.ensure_schema()

    assert database.version == 4
    statements = database.applied_statements
    assert any(
        "ALTER TABLE events ADD COLUMN IF NOT EXISTS occurred_at TIMESTAMPTZ" in item
        for item in statements
    )
    assert any(
        "pg_input_is_valid(" in item
        and "payload->>'occurred_at'" in item
        and "ELSE received_at" in item
        for item in statements
    )
    assert any(
        "ALTER TABLE events ALTER COLUMN occurred_at SET NOT NULL" in item
        for item in statements
    )
    assert "DROP INDEX IF EXISTS events_event_type_idx" in statements
    assert any(
        "events_event_type_occurred_at_idx" in item
        and "occurred_at DESC" in item
        for item in statements
    )


def test_failed_timestamp_migration_rolls_back_version_and_statements(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = FakeDatabase()
    database.version = 1
    database.fail_on = "ALTER TABLE events ADD COLUMN"
    install_fake_database(monkeypatch, database)
    store = storage.PostgresStore("postgresql://test")

    with pytest.raises(RuntimeError, match="simulated migration failure"):
        store.ensure_schema()

    assert database.version == 1
    assert store._schema_ready is False


def test_upgrade_from_v2_adds_threat_intel_cache_expiry_index(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = FakeDatabase()
    database.version = 2
    install_fake_database(monkeypatch, database)
    store = storage.PostgresStore("postgresql://test")

    store.ensure_schema()

    assert database.version == 4
    assert any(
        "threat_intel_cache_expires_at_idx" in item
        and "ON threat_intel_cache (expires_at)" in item
        for item in database.applied_statements
    )


def test_failed_cache_index_migration_rolls_back_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = FakeDatabase()
    database.version = 2
    database.fail_on = "threat_intel_cache_expires_at_idx"
    install_fake_database(monkeypatch, database)
    store = storage.PostgresStore("postgresql://test")

    with pytest.raises(RuntimeError, match="simulated migration failure"):
        store.ensure_schema()

    assert database.version == 2
    assert store._schema_ready is False


def test_upgrade_from_v3_backfills_legacy_audit_rows_in_chain_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = FakeDatabase()
    database.version = 3
    occurred_at = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    database.audit_rows = [
        {
            "audit_id": 4,
            "occurred_at": occurred_at,
            "actor_id": None,
            "action": "integration.registered",
            "target_id": "router-lab",
            "details": {"kind": "openwrt", "enabled": True},
            "previous_hash": None,
            "record_hash": None,
        },
        {
            "audit_id": 9,
            "occurred_at": occurred_at,
            "actor_id": "operator",
            "action": "integration.updated",
            "target_id": "router-lab",
            "details": {"display_name": "Lab router"},
            "previous_hash": None,
            "record_hash": None,
        },
    ]
    install_fake_database(monkeypatch, database)
    store = storage.PostgresStore("postgresql://test")

    store.ensure_schema()

    first, second = database.audit_rows
    assert first["previous_hash"] == GENESIS_AUDIT_HASH
    assert first["record_hash"] == audit_record_hash(
        audit_id=4,
        occurred_at=occurred_at,
        actor_id=None,
        action="integration.registered",
        target_id="router-lab",
        details={"kind": "openwrt", "enabled": True},
        previous_hash=GENESIS_AUDIT_HASH,
    )
    assert second["previous_hash"] == first["record_hash"]
    assert second["record_hash"] == audit_record_hash(
        audit_id=9,
        occurred_at=occurred_at,
        actor_id="operator",
        action="integration.updated",
        target_id="router-lab",
        details={"display_name": "Lab router"},
        previous_hash=str(first["record_hash"]),
    )
    assert database.audit_chain_head == (9, second["record_hash"])
    assert database.version == 4


def test_failed_audit_chain_migration_rolls_back_backfill(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = FakeDatabase()
    database.version = 3
    occurred_at = datetime(2026, 1, 2, tzinfo=UTC)
    legacy_row = {
        "audit_id": 1,
        "occurred_at": occurred_at,
        "actor_id": None,
        "action": "event.ingested",
        "target_id": "router-lab",
        "details": {},
        "previous_hash": None,
        "record_hash": None,
    }
    database.audit_rows = [dict(legacy_row)]
    database.fail_on = "ALTER TABLE audit_records ALTER COLUMN previous_hash SET NOT NULL"
    install_fake_database(monkeypatch, database)
    store = storage.PostgresStore("postgresql://test")

    with pytest.raises(RuntimeError, match="simulated migration failure"):
        store.ensure_schema()

    assert database.version == 3
    assert database.audit_rows == [legacy_row]
    assert database.audit_chain_head is None
    assert store._schema_ready is False


def test_audit_chain_migration_rejects_partial_legacy_hashes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = FakeDatabase()
    database.version = 3
    database.audit_rows = [
        {
            "audit_id": 1,
            "occurred_at": datetime(2026, 1, 2, tzinfo=UTC),
            "actor_id": None,
            "action": "event.ingested",
            "target_id": "router-lab",
            "details": {},
            "previous_hash": GENESIS_AUDIT_HASH,
            "record_hash": None,
        }
    ]
    install_fake_database(monkeypatch, database)
    store = storage.PostgresStore("postgresql://test")

    with pytest.raises(
        storage.StorageConfigurationError,
        match="unexpected chain hashes",
    ):
        store.ensure_schema()

    assert database.version == 3
    assert database.audit_chain_head is None
    assert store._schema_ready is False


def test_database_newer_than_application_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = FakeDatabase()
    database.version = 4
    install_fake_database(monkeypatch, database)
    store = storage.PostgresStore("postgresql://test")

    with pytest.raises(
        storage.StorageConfigurationError,
        match="newer than this application",
    ):
        store.ensure_schema()

    assert store._schema_ready is False
