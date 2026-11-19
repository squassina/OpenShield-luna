"""Capture and compare exact PostgreSQL table counts for an isolated restore drill."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

FORMAT_VERSION = 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--statement-timeout-ms",
        type=int,
        default=120_000,
        help="Per-statement PostgreSQL timeout in milliseconds (default: 120000)",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    capture = commands.add_parser("capture", help="Capture a source database manifest")
    capture.add_argument("--output", required=True, type=Path)
    verify = commands.add_parser("verify", help="Compare a restored database with a manifest")
    verify.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args()
    if not 1_000 <= args.statement_timeout_ms <= 600_000:
        parser.error("--statement-timeout-ms must be between 1000 and 600000")
    return args


def _quote_identifier(value: str) -> str:
    """Quote a database-provided identifier before interpolating it into SQL."""
    return '"' + value.replace('"', '""') + '"'


def collect_manifest(connection: Any, statement_timeout_ms: int) -> dict[str, object]:
    """Read exact row counts and migration history in one read-only snapshot."""
    with connection.cursor() as cursor:
        cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        cursor.execute(
            "SELECT set_config('statement_timeout', %s, true)",
            (f"{statement_timeout_ms}ms",),
        )
        cursor.execute(
            "SELECT current_database(), current_setting('server_version'), "
            "current_setting('server_version_num')::integer"
        )
        database_name, server_version, version_number = cursor.fetchone()
        postgres_major = int(version_number) // 10_000

        cursor.execute(
            "SELECT table_schema, table_name FROM information_schema.tables "
            "WHERE table_schema = 'public' AND table_type = 'BASE TABLE' "
            "ORDER BY table_schema, table_name"
        )
        tables: dict[str, int] = {}
        for schema_name, table_name in cursor.fetchall():
            statement = (
                f"SELECT COUNT(*) FROM {_quote_identifier(schema_name)}."
                f"{_quote_identifier(table_name)}"
            )
            cursor.execute(statement)
            count = cursor.fetchone()[0]
            tables[f"{schema_name}.{table_name}"] = int(count)

        if "public.schema_migrations" not in tables:
            raise RuntimeError("public.schema_migrations is missing from the database")

        cursor.execute(
            "SELECT version, name FROM public.schema_migrations ORDER BY version"
        )
        migrations = [
            {"version": int(version), "name": str(name)}
            for version, name in cursor.fetchall()
        ]

    return {
        "format_version": FORMAT_VERSION,
        "captured_at": datetime.now(UTC).isoformat(),
        "source_database": str(database_name),
        "postgres_version": str(server_version),
        "postgres_major": postgres_major,
        "schema_migrations": migrations,
        "tables": tables,
    }


def validate_manifest(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or value.get("format_version") != FORMAT_VERSION:
        raise ValueError("Unsupported or invalid restore manifest format")
    postgres_major = value.get("postgres_major")
    source_database = value.get("source_database")
    tables = value.get("tables")
    migrations = value.get("schema_migrations")
    if not isinstance(source_database, str) or not source_database:
        raise ValueError("Manifest source_database must be a non-empty string")
    if not isinstance(postgres_major, int) or postgres_major < 10:
        raise ValueError("Manifest postgres_major must be a valid integer")
    if not isinstance(tables, dict) or not tables:
        raise ValueError("Manifest tables must be a non-empty object")
    if not all(
        isinstance(name, str)
        and isinstance(count, int)
        and not isinstance(count, bool)
        and count >= 0
        for name, count in tables.items()
    ):
        raise ValueError("Manifest table counts must be non-negative integers")
    if not isinstance(migrations, list) or not all(
        isinstance(item, dict)
        and isinstance(item.get("version"), int)
        and not isinstance(item.get("version"), bool)
        and isinstance(item.get("name"), str)
        for item in migrations
    ):
        raise ValueError("Manifest schema_migrations must contain version/name entries")
    return value


def compare_manifests(
    expected: dict[str, object], actual: dict[str, object]
) -> dict[str, object]:
    expected_tables = expected["tables"]
    actual_tables = actual["tables"]
    assert isinstance(expected_tables, dict)
    assert isinstance(actual_tables, dict)

    missing_tables = sorted(set(expected_tables) - set(actual_tables))
    unexpected_tables = sorted(set(actual_tables) - set(expected_tables))
    row_count_mismatches = {
        name: {"expected": expected_tables[name], "actual": actual_tables[name]}
        for name in sorted(set(expected_tables) & set(actual_tables))
        if expected_tables[name] != actual_tables[name]
    }
    postgres_major_matches = expected["postgres_major"] == actual["postgres_major"]
    migrations_match = expected["schema_migrations"] == actual["schema_migrations"]
    same_database_name = expected["source_database"] == actual["source_database"]
    matches = (
        not same_database_name
        and postgres_major_matches
        and migrations_match
        and not missing_tables
        and not unexpected_tables
        and not row_count_mismatches
    )
    return {
        "matches": matches,
        "source_database": expected.get("source_database"),
        "restored_database": actual.get("source_database"),
        "same_database_name": same_database_name,
        "postgres_major_matches": postgres_major_matches,
        "expected_postgres_major": expected["postgres_major"],
        "actual_postgres_major": actual["postgres_major"],
        "schema_migrations_match": migrations_match,
        "missing_tables": missing_tables,
        "unexpected_tables": unexpected_tables,
        "row_count_mismatches": row_count_mismatches,
        "table_count": len(expected_tables),
    }


def write_manifest(path: Path, manifest: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as output:
            temporary_path = Path(output.name)
            json.dump(manifest, output, indent=2)
            output.write("\n")
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _load_manifest(path: Path) -> dict[str, object]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read manifest {path}: {exc}") from exc
    return validate_manifest(raw)


def main() -> int:
    import psycopg

    args = parse_args()
    dsn = os.getenv("OPENSHIELD_DATABASE_URL", "").strip()
    if not dsn:
        print("Set OPENSHIELD_DATABASE_URL to the source or restored PostgreSQL database.", file=sys.stderr)
        return 2

    try:
        expected = _load_manifest(args.manifest) if args.command == "verify" else None
        with psycopg.connect(dsn, connect_timeout=5) as connection:
            actual = collect_manifest(connection, args.statement_timeout_ms)
        if args.command == "capture":
            write_manifest(args.output, actual)
            print(
                json.dumps(
                    {
                        "captured": True,
                        "output": str(args.output),
                        "table_count": len(actual["tables"]),
                        "postgres_major": actual["postgres_major"],
                        "schema_migrations": actual["schema_migrations"],
                    },
                    indent=2,
                )
            )
            return 0

        assert expected is not None
        result = compare_manifests(expected, actual)
        print(json.dumps(result, indent=2))
        return 0 if result["matches"] else 1
    except (OSError, psycopg.Error, RuntimeError, TypeError, ValueError) as exc:
        print(f"restore verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
