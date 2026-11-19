import os
import stat
import subprocess
from pathlib import Path

SCRIPT_ROOT = next(
    parent for parent in Path(__file__).resolve().parents if (parent / "scripts/backup.sh").is_file()
)
BACKUP_SCRIPT = SCRIPT_ROOT / "scripts" / "backup.sh"
RESTORE_SCRIPT = SCRIPT_ROOT / "scripts" / "restore.sh"


def make_fake_postgres_tools(tmp_path: Path) -> dict[str, str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    pg_dump = bin_dir / "pg_dump"
    pg_dump.write_text(
        """#!/bin/sh
set -eu
output=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--file" ]; then
    shift
    output="$1"
  fi
  shift
done
[ -n "$output" ]
printf '%s' "${PG_DUMP_CONTENT:-valid-archive}" > "$output"
exit "${PG_DUMP_EXIT_CODE:-0}"
""",
        encoding="utf-8",
    )
    pg_restore = bin_dir / "pg_restore"
    pg_restore.write_text(
        """#!/bin/sh
set -eu
if [ "${1:-}" = "--list" ]; then
  [ "${PG_RESTORE_LIST_FAIL:-0}" != "1" ] || exit 23
  if [ -f "$2" ] && grep -q 'valid-archive' "$2"; then
    exit 0
  fi
  exit 12
fi
printf '%s\\n' "$*" >> "${PG_RESTORE_LOG:?}"
exit "${PG_RESTORE_EXIT_CODE:-0}"
""",
        encoding="utf-8",
    )
    pg_dump.chmod(0o755)
    pg_restore.chmod(0o755)

    environment = os.environ.copy()
    environment["PATH"] = f"{bin_dir}:{environment['PATH']}"
    environment["OPENSHIELD_DATABASE_URL"] = "postgresql://openshield@localhost/openshield"
    environment["PG_RESTORE_LOG"] = str(tmp_path / "pg_restore.log")
    return environment


def run_script(
    script: Path, environment: dict[str, str], *args: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["sh", str(script), *args],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )


def test_backup_publishes_verified_archive_with_restricted_permissions(tmp_path: Path) -> None:
    environment = make_fake_postgres_tools(tmp_path)
    backup_dir = tmp_path / "backups"

    result = run_script(BACKUP_SCRIPT, environment, str(backup_dir))

    assert result.returncode == 0, result.stderr
    archives = list(backup_dir.glob("openshield-*.dump"))
    assert len(archives) == 1
    assert archives[0].read_text(encoding="utf-8") == "valid-archive"
    assert stat.S_IMODE(archives[0].stat().st_mode) == 0o600
    assert list(backup_dir.glob(".openshield-backup.*")) == []


def test_backup_removes_partial_archive_when_pg_dump_fails(tmp_path: Path) -> None:
    environment = make_fake_postgres_tools(tmp_path)
    environment["PG_DUMP_EXIT_CODE"] = "17"
    backup_dir = tmp_path / "backups"

    result = run_script(BACKUP_SCRIPT, environment, str(backup_dir))

    assert result.returncode == 17
    assert list(backup_dir.iterdir()) == []


def test_backup_removes_archive_when_verification_fails(tmp_path: Path) -> None:
    environment = make_fake_postgres_tools(tmp_path)
    environment["PG_RESTORE_LIST_FAIL"] = "1"
    backup_dir = tmp_path / "backups"

    result = run_script(BACKUP_SCRIPT, environment, str(backup_dir))

    assert result.returncode == 1
    assert "Backup verification failed" in result.stderr
    assert list(backup_dir.iterdir()) == []


def test_restore_requires_explicit_confirmation_before_writing(tmp_path: Path) -> None:
    environment = make_fake_postgres_tools(tmp_path)
    archive = tmp_path / "source.dump"
    archive.write_text("valid-archive", encoding="utf-8")

    result = run_script(RESTORE_SCRIPT, environment, str(archive))

    assert result.returncode == 1
    assert "OPENSHIELD_RESTORE_CONFIRM=YES" in result.stderr
    assert not Path(environment["PG_RESTORE_LOG"]).exists()


def test_restore_uses_single_transaction_and_stops_on_error(tmp_path: Path) -> None:
    environment = make_fake_postgres_tools(tmp_path)
    environment["OPENSHIELD_RESTORE_CONFIRM"] = "YES"
    archive = tmp_path / "source.dump"
    archive.write_text("valid-archive", encoding="utf-8")

    result = run_script(RESTORE_SCRIPT, environment, str(archive))

    assert result.returncode == 0, result.stderr
    arguments = Path(environment["PG_RESTORE_LOG"]).read_text(encoding="utf-8")
    assert "--single-transaction" in arguments
    assert "--exit-on-error" in arguments
    assert "--no-owner" in arguments
    assert "--no-privileges" in arguments
    assert "--dbname postgresql://openshield@localhost/openshield" in arguments


def test_restore_propagates_transactional_restore_failure(tmp_path: Path) -> None:
    environment = make_fake_postgres_tools(tmp_path)
    environment["OPENSHIELD_RESTORE_CONFIRM"] = "YES"
    environment["PG_RESTORE_EXIT_CODE"] = "14"
    archive = tmp_path / "source.dump"
    archive.write_text("valid-archive", encoding="utf-8")

    result = run_script(RESTORE_SCRIPT, environment, str(archive))

    assert result.returncode == 14
    assert "--single-transaction" in Path(environment["PG_RESTORE_LOG"]).read_text(
        encoding="utf-8"
    )
