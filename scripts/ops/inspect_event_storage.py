"""Collect read-only PostgreSQL storage statistics and event-list query plans."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from typing import Any

import psycopg


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--integration-id", default="benchmark-zeek")
    parser.add_argument("--event-type", default="network.zeek.conn")
    parser.add_argument("--severity", default="info")
    parser.add_argument(
        "--analyze",
        action="store_true",
        help="Execute EXPLAIN ANALYZE (use staging only; runs the SELECT queries)",
    )
    parser.add_argument("--statement-timeout-ms", type=int, default=30_000)
    args = parser.parse_args()
    if not 1_000 <= args.statement_timeout_ms <= 120_000:
        parser.error("--statement-timeout-ms must be between 1000 and 120000")
    return args


def event_query_specs(
    integration_id: str, event_type: str, severity: str
) -> list[tuple[str, str, tuple[object, ...]]]:
    """Mirror the event-list filters and ordering used by PostgresStore.list_events_page."""
    cursor_time = datetime.now(UTC)
    return [
        (
            "recent_page",
            """SELECT payload, received_at, event_id FROM events
            ORDER BY received_at DESC, event_id DESC LIMIT 201""",
            (),
        ),
        (
            "integration_page",
            """SELECT payload, received_at, event_id FROM events
            WHERE payload #>> '{source,integration_id}' = %s
            ORDER BY received_at DESC, event_id DESC LIMIT 201""",
            (integration_id,),
        ),
        (
            "integration_type_severity_page",
            """SELECT payload, received_at, event_id FROM events
            WHERE payload #>> '{source,integration_id}' = %s
            AND payload->>'event_type' = %s
            AND payload->>'severity' = %s
            ORDER BY received_at DESC, event_id DESC LIMIT 201""",
            (integration_id, event_type, severity),
        ),
        (
            "integration_cursor_page",
            """SELECT payload, received_at, event_id FROM events
            WHERE payload #>> '{source,integration_id}' = %s
            AND (received_at, event_id) < (%s, %s)
            ORDER BY received_at DESC, event_id DESC LIMIT 201""",
            (integration_id, cursor_time, "~"),
        ),
    ]


def _read_plan(
    cursor: Any,
    statement: str,
    parameters: tuple[object, ...],
    analyze: bool,
) -> Any:
    options = "ANALYZE, BUFFERS, TIMING OFF, FORMAT JSON" if analyze else "FORMAT JSON"
    cursor.execute(f"EXPLAIN ({options}) {statement}", parameters)
    result = cursor.fetchone()[0]
    if isinstance(result, str):
        result = json.loads(result)
    return result[0] if isinstance(result, list) else result


def collect_diagnostics(
    connection: Any, args: argparse.Namespace
) -> dict[str, object]:
    with connection.cursor() as cursor:
        cursor.execute("SET TRANSACTION READ ONLY")
        cursor.execute(
            "SELECT set_config('statement_timeout', %s, true)",
            (str(args.statement_timeout_ms),),
        )

        cursor.execute(
            "SELECT current_database(), current_setting('server_version'), "
            "pg_database_size(current_database())"
        )
        database_name, server_version, database_size = cursor.fetchone()

        cursor.execute(
            "SELECT COALESCE(n_live_tup, 0), COALESCE(n_dead_tup, 0), "
            "pg_total_relation_size('events'::regclass), "
            "pg_relation_size('events'::regclass), "
            "pg_indexes_size('events'::regclass), last_analyze, last_autoanalyze "
            "FROM pg_stat_user_tables WHERE relid = 'events'::regclass"
        )
        event_stats = cursor.fetchone()
        if event_stats is None:
            raise RuntimeError("The events table was not found in the current search path")

        cursor.execute(
            "SELECT stats.indexrelname, definitions.indexdef, stats.idx_scan, "
            "stats.idx_tup_read, stats.idx_tup_fetch, "
            "pg_relation_size(stats.indexrelid) "
            "FROM pg_stat_user_indexes AS stats "
            "JOIN pg_indexes AS definitions "
            "ON definitions.schemaname = stats.schemaname "
            "AND definitions.indexname = stats.indexrelname "
            "WHERE stats.relid = 'events'::regclass "
            "ORDER BY stats.indexrelname"
        )
        indexes = [
            {
                "name": row[0],
                "definition": row[1],
                "scans_since_stats_reset": row[2],
                "tuples_read": row[3],
                "tuples_fetched": row[4],
                "size_bytes": row[5],
            }
            for row in cursor.fetchall()
        ]

        plans = {}
        for name, statement, parameters in event_query_specs(
            args.integration_id, args.event_type, args.severity
        ):
            plans[name] = _read_plan(cursor, statement, parameters, args.analyze)

    return {
        "captured_at": datetime.now(UTC).isoformat(),
        "database": {
            "name": database_name,
            "server_version": server_version,
            "size_bytes": database_size,
        },
        "events": {
            "estimated_live_rows": event_stats[0],
            "estimated_dead_rows": event_stats[1],
            "total_bytes": event_stats[2],
            "table_bytes": event_stats[3],
            "index_bytes": event_stats[4],
            "last_analyze": event_stats[5].isoformat() if event_stats[5] else None,
            "last_autoanalyze": (
                event_stats[6].isoformat() if event_stats[6] else None
            ),
        },
        "indexes": indexes,
        "query_parameters": {
            "integration_id": args.integration_id,
            "event_type": args.event_type,
            "severity": args.severity,
        },
        "query_plans": plans,
        "explain_analyze_executed": args.analyze,
        "statement_timeout_ms": args.statement_timeout_ms,
    }


def main() -> int:
    args = parse_args()
    dsn = os.getenv("OPENSHIELD_DATABASE_URL", "").strip()
    if not dsn:
        print("Set OPENSHIELD_DATABASE_URL to the target PostgreSQL database.", file=sys.stderr)
        return 2

    try:
        with psycopg.connect(dsn, connect_timeout=5) as connection:
            report = collect_diagnostics(connection, args)
    except (psycopg.Error, RuntimeError, ValueError) as exc:
        print(f"database diagnostics failed: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(report, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
