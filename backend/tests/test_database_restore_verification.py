import json
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

script_relative_path = Path("scripts/ops/verify_database_restore.py")
script_path = next(
    parent / script_relative_path
    for parent in Path(__file__).resolve().parents
    if (parent / script_relative_path).is_file()
)
script_spec = spec_from_file_location("verify_database_restore", script_path)
assert script_spec is not None and script_spec.loader is not None
restore_verifier = module_from_spec(script_spec)
script_spec.loader.exec_module(restore_verifier)


class FakeDatabase:
    def __init__(self, database_name: str = "openshield_source") -> None:
        self.database_name = database_name
        self.version_number = 160006
        self.version = "16.6"
        self.tables = {
            "public.events": 25,
            "public.integrations": 3,
            "public.schema_migrations": 3,
        }
        self.migrations = [
            (1, "initial schema"),
            (2, "typed event occurrence timestamps"),
            (3, "threat intelligence cache expiry index"),
        ]
        self.statements: list[str] = []


class FakeCursor:
    def __init__(self, database: FakeDatabase) -> None:
        self.database = database
        self.last_statement = ""

    def __enter__(self):
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def execute(self, statement: str, parameters: tuple[object, ...] = ()) -> None:
        self.last_statement = statement
        self.database.statements.append(statement)

    def fetchone(self):
        if "current_database()" in self.last_statement:
            return (
                self.database.database_name,
                self.database.version,
                self.database.version_number,
            )
        if self.last_statement.startswith("SELECT COUNT(*) FROM"):
            table = self.last_statement.removeprefix("SELECT COUNT(*) FROM ")
            schema, name = table.split(".", 1)
            key = f"{schema.strip(chr(34))}.{name.strip(chr(34))}"
            return (self.database.tables[key],)
        raise AssertionError(f"Unexpected fetchone: {self.last_statement}")

    def fetchall(self):
        if "information_schema.tables" in self.last_statement:
            return [tuple(name.split(".", 1)) for name in self.database.tables]
        if "FROM public.schema_migrations" in self.last_statement:
            return self.database.migrations
        raise AssertionError(f"Unexpected fetchall: {self.last_statement}")


class FakeConnection:
    def __init__(self, database: FakeDatabase) -> None:
        self.database = database
        self.cursor_instance = FakeCursor(database)

    def cursor(self) -> FakeCursor:
        return self.cursor_instance


def test_collect_manifest_reads_exact_counts_and_migrations_in_read_only_snapshot() -> None:
    database = FakeDatabase()
    connection = FakeConnection(database)

    manifest = restore_verifier.collect_manifest(connection, statement_timeout_ms=60_000)

    assert manifest["format_version"] == 1
    assert manifest["source_database"] == "openshield_source"
    assert manifest["postgres_major"] == 16
    assert manifest["tables"] == database.tables
    assert manifest["schema_migrations"] == [
        {"version": 1, "name": "initial schema"},
        {"version": 2, "name": "typed event occurrence timestamps"},
        {"version": 3, "name": "threat intelligence cache expiry index"},
    ]
    assert database.statements[0] == (
        "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
    )
    assert "set_config('statement_timeout'" in database.statements[1]
    assert all(statement.startswith(("SET ", "SELECT ")) for statement in database.statements)


def test_identifier_quoting_escapes_embedded_quotes() -> None:
    assert restore_verifier._quote_identifier('event"log') == '"event""log"'


def test_compare_manifests_requires_a_distinct_target_and_equal_data() -> None:
    source = FakeDatabase("openshield_source")
    restored = FakeDatabase("openshield_restore_test")
    expected = restore_verifier.collect_manifest(
        FakeConnection(source), statement_timeout_ms=60_000
    )
    actual = restore_verifier.collect_manifest(
        FakeConnection(restored), statement_timeout_ms=60_000
    )

    result = restore_verifier.compare_manifests(expected, actual)

    assert result["matches"] is True
    assert result["same_database_name"] is False
    assert result["row_count_mismatches"] == {}

    same_database = restore_verifier.compare_manifests(
        expected,
        restore_verifier.collect_manifest(
            FakeConnection(FakeDatabase("openshield_source")), statement_timeout_ms=60_000
        ),
    )
    assert same_database["matches"] is False
    assert same_database["same_database_name"] is True


def test_compare_manifests_reports_table_migration_and_version_differences() -> None:
    expected = {
        "source_database": "openshield_source",
        "postgres_major": 16,
        "schema_migrations": [{"version": 3, "name": "latest"}],
        "tables": {"public.events": 20, "public.integrations": 2},
    }
    actual = {
        "source_database": "openshield_restore_test",
        "postgres_major": 15,
        "schema_migrations": [{"version": 2, "name": "previous"}],
        "tables": {"public.events": 18, "public.audit_records": 5},
    }

    result = restore_verifier.compare_manifests(expected, actual)

    assert result["matches"] is False
    assert result["missing_tables"] == ["public.integrations"]
    assert result["unexpected_tables"] == ["public.audit_records"]
    assert result["row_count_mismatches"] == {
        "public.events": {"expected": 20, "actual": 18}
    }
    assert result["postgres_major_matches"] is False
    assert result["schema_migrations_match"] is False


def test_validate_manifest_rejects_invalid_counts_and_migration_entries() -> None:
    valid = {
        "format_version": 1,
        "source_database": "openshield_source",
        "postgres_major": 16,
        "schema_migrations": [{"version": 1, "name": "initial"}],
        "tables": {"public.events": 1},
    }

    assert restore_verifier.validate_manifest(valid) is valid

    invalid = {**valid, "tables": {"public.events": -1}}
    try:
        restore_verifier.validate_manifest(invalid)
    except ValueError as exc:
        assert "non-negative integers" in str(exc)
    else:
        raise AssertionError("Negative row count was accepted")


def test_write_manifest_uses_restrictive_permissions_and_valid_json(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "restore-manifest.json"
    manifest = {
        "format_version": 1,
        "source_database": "openshield_source",
        "postgres_major": 16,
        "schema_migrations": [{"version": 1, "name": "initial"}],
        "tables": {"public.events": 1},
    }

    restore_verifier.write_manifest(target, manifest)

    assert target.is_file()
    assert target.stat().st_mode & 0o777 == 0o600
    assert restore_verifier.validate_manifest(
        json.loads(target.read_text(encoding="utf-8"))
    ) == manifest
