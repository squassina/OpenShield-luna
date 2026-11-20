from __future__ import annotations

import hashlib
import io
import json
from datetime import UTC, datetime
from typing import Any, Self

from openshield.core.audit_integrity import GENESIS_AUDIT_HASH, audit_record_hash
from openshield.core.storage_audit import PostgresAuditStoreMixin


class FakeAuditCursor:
    def __init__(
        self,
        rows: list[tuple[object, ...]],
        chain_head: tuple[int, str] | None,
    ) -> None:
        self.rows = rows
        self.chain_head = chain_head
        self.position = 0
        self.row: tuple[object, ...] | None = None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def execute(self, statement: str, _params: tuple[Any, ...] | None = None) -> None:
        normalized = " ".join(statement.split())
        if normalized.startswith("SELECT last_audit_id, last_hash FROM audit_chain_state"):
            self.row = self.chain_head

    def fetchmany(self, size: int) -> list[tuple[object, ...]]:
        rows = self.rows[self.position : self.position + size]
        self.position += len(rows)
        return rows

    def fetchone(self) -> tuple[object, ...] | None:
        return self.row


class FakeAuditConnection:
    def __init__(self, cursor: FakeAuditCursor) -> None:
        self._cursor = cursor

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def cursor(self) -> FakeAuditCursor:
        return self._cursor


class FakeAuditStore(PostgresAuditStoreMixin):
    def __init__(
        self,
        rows: list[tuple[object, ...]],
        chain_head: tuple[int, str] | None,
    ) -> None:
        self.cursor = FakeAuditCursor(rows, chain_head)

    def _connect(self) -> FakeAuditConnection:
        return FakeAuditConnection(self.cursor)


def make_audit_rows() -> tuple[list[tuple[object, ...]], tuple[int, str]]:
    occurred_at = datetime(2026, 11, 20, 10, 0, tzinfo=UTC)
    first_hash = audit_record_hash(
        audit_id=2,
        occurred_at=occurred_at,
        actor_id="operator",
        action="integration.updated",
        target_id="router",
        details={"enabled": True},
        previous_hash=GENESIS_AUDIT_HASH,
    )
    second_hash = audit_record_hash(
        audit_id=5,
        occurred_at=occurred_at,
        actor_id=None,
        action="gateway.connected",
        target_id="gateway-1",
        details={"version": "1.0"},
        previous_hash=first_hash,
    )
    rows = [
        (
            2, occurred_at, "operator", "integration.updated", "router",
            {"enabled": True}, GENESIS_AUDIT_HASH, first_hash,
        ),
        (
            5, occurred_at, None, "gateway.connected", "gateway-1",
            {"version": "1.0"}, first_hash, second_hash,
        ),
    ]
    return rows, (5, second_hash)


def test_export_audit_snapshot_writes_verified_ndjson_checkpoint() -> None:
    rows, chain_head = make_audit_rows()
    output = io.StringIO()

    result = FakeAuditStore(rows, chain_head).export_audit_snapshot(output)
    lines = [json.loads(line) for line in output.getvalue().splitlines()]

    assert result["valid"] is True
    assert result["records_checked"] == 2
    assert result["last_audit_id"] == 5
    assert len(result["records_sha256"]) == 64
    assert [line["type"] for line in lines] == ["header", "record", "record", "checkpoint"]
    assert lines[-1]["head_hash"] == chain_head[1]
    record_bytes = "".join(
        line + "\\n"
        for line in output.getvalue().splitlines()
        if json.loads(line)["type"] == "record"
    ).encode("utf-8")
    assert hashlib.sha256(record_bytes).hexdigest() == result["records_sha256"]
    assert lines[-1]["records_sha256"] == result["records_sha256"]


def test_export_audit_snapshot_does_not_emit_checkpoint_for_invalid_chain() -> None:
    rows, chain_head = make_audit_rows()
    first = list(rows[0])
    first[7] = "f" * 64
    output = io.StringIO()

    result = FakeAuditStore([tuple(first), rows[1]], chain_head).export_audit_snapshot(output)

    assert result["valid"] is False
    assert result["error"] == "record_hash_mismatch"
    assert "checkpoint" not in output.getvalue()


def test_export_audit_snapshot_rejects_a_mismatched_persisted_head() -> None:
    rows, _ = make_audit_rows()
    output = io.StringIO()

    result = FakeAuditStore(rows, (5, "f" * 64)).export_audit_snapshot(output)

    assert result["valid"] is False
    assert result["error"] == "chain_head_mismatch"
    assert "checkpoint" not in output.getvalue()


def test_export_audit_snapshot_supports_an_empty_audit_chain() -> None:
    output = io.StringIO()

    result = FakeAuditStore([], (0, GENESIS_AUDIT_HASH)).export_audit_snapshot(output)
    lines = [json.loads(line) for line in output.getvalue().splitlines()]

    assert result["valid"] is True
    assert result["records_checked"] == 0
    assert lines[-1]["type"] == "checkpoint"
    assert lines[-1]["head_hash"] == GENESIS_AUDIT_HASH
