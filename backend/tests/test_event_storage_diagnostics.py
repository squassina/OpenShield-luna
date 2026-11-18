from datetime import UTC, datetime
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

script_relative_path = Path("scripts/ops/inspect_event_storage.py")
script_path = next(
    parent / script_relative_path
    for parent in Path(__file__).resolve().parents
    if (parent / script_relative_path).is_file()
)
script_spec = spec_from_file_location("inspect_event_storage", script_path)
assert script_spec is not None and script_spec.loader is not None
diagnostics = module_from_spec(script_spec)
script_spec.loader.exec_module(diagnostics)


class FakeCursor:
    def __init__(self) -> None:
        self.last_statement = ""
        self.executed: list[tuple[str, tuple[object, ...]]] = []

    def __enter__(self):
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def execute(self, statement: str, parameters: tuple[object, ...] = ()) -> None:
        self.last_statement = statement
        self.executed.append((statement, parameters))

    def fetchone(self):
        if "current_database()" in self.last_statement:
            return ("openshield_test", "16.4", 1024)
        if "pg_stat_user_tables" in self.last_statement:
            now = datetime.now(UTC)
            return (1200, 12, 8192, 4096, 4096, now, now)
        if self.last_statement.startswith("EXPLAIN"):
            return ([{"Plan": {"Node Type": "Index Scan"}}],)
        raise AssertionError(f"Unexpected fetchone for: {self.last_statement}")

    def fetchall(self):
        assert "pg_stat_user_indexes" in self.last_statement
        return [("events_received_at_idx", "CREATE INDEX ...", 10, 100, 90, 4096)]


class FakeConnection:
    def __init__(self) -> None:
        self.cursor_instance = FakeCursor()

    def cursor(self) -> FakeCursor:
        return self.cursor_instance


def test_event_query_specs_match_list_events_page_filters_and_sort_order() -> None:
    specs = diagnostics.event_query_specs("zeek-lab", "network.zeek.conn", "info")

    assert [spec[0] for spec in specs] == [
        "recent_page",
        "integration_page",
        "integration_type_severity_page",
        "integration_cursor_page",
    ]
    assert "ORDER BY received_at DESC, event_id DESC LIMIT 201" in specs[0][1]
    assert "payload #>> '{source,integration_id}' = %s" in specs[1][1]
    assert "payload->>'event_type' = %s" in specs[2][1]
    assert "payload->>'severity' = %s" in specs[2][1]
    assert "(received_at, event_id) < (%s, %s)" in specs[3][1]
    assert specs[2][2] == ("zeek-lab", "network.zeek.conn", "info")


def test_collect_diagnostics_is_read_only_and_reports_query_plans() -> None:
    for analyze in (False, True):
        connection = FakeConnection()
        args = type(
            "Args",
            (),
            {
                "integration_id": "zeek-lab",
                "event_type": "network.zeek.conn",
                "severity": "info",
                "analyze": analyze,
                "statement_timeout_ms": 15_000,
            },
        )()

        report = diagnostics.collect_diagnostics(connection, args)

        assert report["database"] == {
            "name": "openshield_test",
            "server_version": "16.4",
            "size_bytes": 1024,
        }
        assert report["events"]["estimated_live_rows"] == 1200
        assert report["events"]["total_bytes"] == 8192
        assert len(report["indexes"]) == 1
        assert set(report["query_plans"]) == {
            "recent_page",
            "integration_page",
            "integration_type_severity_page",
            "integration_cursor_page",
        }
        assert report["explain_analyze_executed"] is analyze

        statements = [statement for statement, _ in connection.cursor_instance.executed]
        assert statements[0] == "SET TRANSACTION READ ONLY"
        assert "set_config('statement_timeout'" in statements[1]
        explain_statements = [statement for statement in statements if statement.startswith("EXPLAIN")]
        assert len(explain_statements) == 4
        assert all(("ANALYZE, BUFFERS" in statement) is analyze for statement in explain_statements)
