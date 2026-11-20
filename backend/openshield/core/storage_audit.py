import hashlib
import json
from datetime import UTC, datetime
from typing import TextIO

import psycopg
from psycopg.types.json import Jsonb

from openshield.core.audit_integrity import GENESIS_AUDIT_HASH, audit_record_hash


class StorageConfigurationError(RuntimeError):
    pass


class PostgresAuditStoreMixin:
    """Audit record and integrity persistence for the PostgreSQL store."""

    @staticmethod
    def _backfill_audit_chain(cursor: psycopg.Cursor) -> None:
        """Backfill legacy audit rows in bounded batches inside the migration transaction."""
        cursor.execute(
            """
            SELECT last_audit_id, last_hash
            FROM audit_chain_state
            WHERE chain_id = 1
            FOR UPDATE
            """
        )
        state = cursor.fetchone()
        if state is None or int(state[0]) != 0 or state[1] != GENESIS_AUDIT_HASH:
            raise StorageConfigurationError(
                "Audit chain state is not at its expected migration baseline"
            )

        last_audit_id = 0
        previous_hash = GENESIS_AUDIT_HASH
        while True:
            cursor.execute(
                """
                SELECT audit_id, occurred_at, actor_id, action, target_id, details,
                       previous_hash, record_hash
                FROM audit_records
                WHERE audit_id > %s
                ORDER BY audit_id
                LIMIT 500
                FOR UPDATE
                """,
                (last_audit_id,),
            )
            rows = cursor.fetchall()
            if not rows:
                break

            for row in rows:
                if row[6] is not None or row[7] is not None:
                    raise StorageConfigurationError(
                        "Legacy audit records contain unexpected chain hashes"
                    )
                audit_id = int(row[0])
                record_hash = audit_record_hash(
                    audit_id=audit_id,
                    occurred_at=row[1],
                    actor_id=row[2],
                    action=str(row[3]),
                    target_id=row[4],
                    details=row[5],
                    previous_hash=previous_hash,
                )
                cursor.execute(
                    """
                    UPDATE audit_records
                    SET previous_hash = %s, record_hash = %s
                    WHERE audit_id = %s
                    """,
                    (previous_hash, record_hash, audit_id),
                )
                last_audit_id = audit_id
                previous_hash = record_hash

        cursor.execute(
            """
            UPDATE audit_chain_state
            SET last_audit_id = %s, last_hash = %s
            WHERE chain_id = 1
            """,
            (last_audit_id, previous_hash),
        )

    @staticmethod
    def _insert_audit(
        cursor: psycopg.Cursor,
        action: str,
        actor_id: str | None,
        target_id: str | None,
        details: dict[str, object],
    ) -> None:
        cursor.execute(
            """
            SELECT last_audit_id, last_hash
            FROM audit_chain_state
            WHERE chain_id = 1
            FOR UPDATE
            """
        )
        head = cursor.fetchone()
        if head is None:
            raise StorageConfigurationError("Audit chain state is missing")
        last_audit_id, previous_hash = int(head[0]), str(head[1])

        cursor.execute(
            "SELECT nextval(pg_get_serial_sequence('audit_records', 'audit_id'))"
        )
        sequence_row = cursor.fetchone()
        if sequence_row is None:
            raise StorageConfigurationError("Audit record sequence is unavailable")
        audit_id = int(sequence_row[0])
        if audit_id <= last_audit_id:
            raise StorageConfigurationError("Audit record sequence is behind the chain head")

        occurred_at = datetime.now(UTC)
        record_hash = audit_record_hash(
            audit_id=audit_id,
            occurred_at=occurred_at,
            actor_id=actor_id,
            action=action,
            target_id=target_id,
            details=details,
            previous_hash=previous_hash,
        )
        cursor.execute(
            """
            INSERT INTO audit_records (
                audit_id, occurred_at, actor_id, action, target_id, details,
                previous_hash, record_hash
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                audit_id,
                occurred_at,
                actor_id,
                action,
                target_id,
                Jsonb(details),
                previous_hash,
                record_hash,
            ),
        )
        # The AFTER INSERT trigger advances the persisted chain head atomically.

    def write_audit(
        self,
        action: str,
        actor_id: str | None,
        target_id: str | None,
        details: dict[str, object],
    ) -> None:
        with self._connect() as connection, connection.cursor() as cursor:
            self._insert_audit(cursor, action, actor_id, target_id, details)

    def list_audit(self, limit: int = 100) -> list[dict[str, object]]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT audit_id, occurred_at, actor_id, action, target_id, details,
                       previous_hash, record_hash
                FROM audit_records
                ORDER BY audit_id DESC
                LIMIT %s
                """,
                (limit,),
            )
            rows = cursor.fetchall()
        return [
            {
                "audit_id": row[0],
                "occurred_at": row[1].isoformat(),
                "actor_id": row[2],
                "action": row[3],
                "target_id": row[4],
                "details": row[5],
                "previous_hash": row[6],
                "record_hash": row[7],
            }
            for row in rows
        ]


    def export_audit_snapshot(self, destination: TextIO) -> dict[str, object]:
        """Write a complete, verified audit-chain snapshot as newline-delimited JSON."""
        generated_at = datetime.now(UTC)
        records_digest = hashlib.sha256()

        def write_line(record: dict[str, object], *, is_audit_record: bool = False) -> None:
            encoded = (
                json.dumps(
                    record,
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            destination.write(encoded.decode("utf-8"))
            if is_audit_record:
                records_digest.update(encoded)

        write_line({
            "type": "header",
            "schema_version": 1,
            "generated_at": generated_at.isoformat(),
            "hash_algorithm": "sha256",
        })

        previous_hash = GENESIS_AUDIT_HASH
        last_audit_id = 0
        records_checked = 0
        error: str | None = None
        stored_head_id: int | None = None
        stored_head_hash: str | None = None

        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            cursor.execute(
                """
                SELECT audit_id, occurred_at, actor_id, action, target_id, details,
                       previous_hash, record_hash
                FROM audit_records
                ORDER BY audit_id
                """
            )
            while rows := cursor.fetchmany(500):
                for row in rows:
                    records_checked += 1
                    audit_id = int(row[0])
                    if row[6] != previous_hash:
                        error = "previous_hash_mismatch"
                        break
                    try:
                        calculated_hash = audit_record_hash(
                            audit_id=audit_id,
                            occurred_at=row[1],
                            actor_id=row[2],
                            action=str(row[3]),
                            target_id=row[4],
                            details=row[5],
                            previous_hash=previous_hash,
                        )
                    except (TypeError, ValueError):
                        error = "record_payload_invalid"
                        break
                    if row[7] != calculated_hash:
                        error = "record_hash_mismatch"
                        break
                    try:
                        occurred_at = row[1].astimezone(UTC).isoformat()
                        write_line(
                            {
                                "type": "record",
                                "audit_id": audit_id,
                                "occurred_at": occurred_at,
                                "actor_id": row[2],
                                "action": str(row[3]),
                                "target_id": row[4],
                                "details": row[5],
                                "previous_hash": row[6],
                                "record_hash": row[7],
                            },
                            is_audit_record=True,
                        )
                    except (TypeError, ValueError):
                        error = "record_payload_invalid"
                        break
                    previous_hash = calculated_hash
                    last_audit_id = audit_id
                if error is not None:
                    break

            cursor.execute(
                """
                SELECT last_audit_id, last_hash
                FROM audit_chain_state
                WHERE chain_id = 1
                """
            )
            head = cursor.fetchone()
            if head is None:
                error = error or "chain_head_missing"
            else:
                stored_head_id = int(head[0])
                stored_head_hash = str(head[1])
                if (stored_head_id, stored_head_hash) != (last_audit_id, previous_hash):
                    error = error or "chain_head_mismatch"

        result: dict[str, object] = {
            "valid": error is None,
            "records_checked": records_checked,
            "last_audit_id": last_audit_id,
            "head_hash": previous_hash,
            "stored_head_audit_id": stored_head_id,
            "stored_head_hash": stored_head_hash,
            "records_sha256": records_digest.hexdigest(),
            "generated_at": generated_at.isoformat(),
            "error": error,
        }
        if error is None:
            write_line({
                "type": "checkpoint",
                "schema_version": 1,
                "valid": True,
                "records_checked": records_checked,
                "last_audit_id": last_audit_id,
                "head_hash": previous_hash,
                "records_sha256": records_digest.hexdigest(),
                "generated_at": generated_at.isoformat(),
            })
        destination.flush()
        return result

    def verify_audit_chain(self) -> dict[str, object]:
        """Verify record ordering, hashes, and the persisted chain head."""
        previous_hash = GENESIS_AUDIT_HASH
        last_audit_id = 0
        records_checked = 0
        error: str | None = None
        stored_head_id: int | None = None
        stored_head_hash: str | None = None

        with self._connect() as connection, connection.cursor() as cursor:
            # Both the record scan and chain-head read must see one database snapshot.
            cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            cursor.execute(
                """
                SELECT audit_id, occurred_at, actor_id, action, target_id, details,
                       previous_hash, record_hash
                FROM audit_records
                ORDER BY audit_id
                """
            )
            while rows := cursor.fetchmany(500):
                for row in rows:
                    records_checked += 1
                    audit_id = int(row[0])
                    if row[6] != previous_hash:
                        error = "previous_hash_mismatch"
                        break
                    try:
                        calculated_hash = audit_record_hash(
                            audit_id=audit_id,
                            occurred_at=row[1],
                            actor_id=row[2],
                            action=str(row[3]),
                            target_id=row[4],
                            details=row[5],
                            previous_hash=previous_hash,
                        )
                    except (TypeError, ValueError):
                        error = "record_payload_invalid"
                        break
                    if row[7] != calculated_hash:
                        error = "record_hash_mismatch"
                        break
                    previous_hash = calculated_hash
                    last_audit_id = audit_id
                if error is not None:
                    break

            cursor.execute(
                """
                SELECT last_audit_id, last_hash
                FROM audit_chain_state
                WHERE chain_id = 1
                """
            )
            head = cursor.fetchone()
            if head is None:
                error = error or "chain_head_missing"
            else:
                stored_head_id = int(head[0])
                stored_head_hash = str(head[1])
                if (stored_head_id, stored_head_hash) != (last_audit_id, previous_hash):
                    error = error or "chain_head_mismatch"

        return {
            "valid": error is None,
            "records_checked": records_checked,
            "last_audit_id": last_audit_id,
            "computed_head_hash": previous_hash,
            "stored_head_audit_id": stored_head_id,
            "stored_head_hash": stored_head_hash,
            "error": error,
        }
