import os
import subprocess
from pathlib import Path


ROOT = next(
    parent for parent in Path(__file__).resolve().parents
    if (parent / "scripts" / "backup.sh").is_file()
)


def _command(path: Path, source: str) -> None:
    path.write_text("#!/bin/sh\nset -eu\n" + source, encoding="utf-8")
    path.chmod(0o755)


def _fake_postgres_tools(tmp_path: Path, *, target_empty: str = "t") -> tuple[Path, Path]:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    pg_dump = bindir / "pg_dump"
    pg_restore = bindir / "pg_restore"
    psql = bindir / "psql"
    _command(
        pg_dump,
        """
output=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--file" ]; then output="$2"; shift 2; else shift; fi
done
[ -n "$output" ]
printf 'fake PostgreSQL dump\\n' > "$output"
""",
    )
    _command(
        pg_restore,
        """
if [ "$1" = "--list" ]; then
  [ -s "$2" ]
  exit
fi
printf 'restore-called\\n' >> "$RESTORE_LOG"
""",
    )
    _command(psql, "printf '%s\\n' \"$RESTORE_TARGET_EMPTY\"\n")
    return bindir, pg_restore


def _env(tmp_path: Path, bindir: Path, **extra: str) -> dict[str, str]:
    return {
        **os.environ,
        "PATH": f"{bindir}:{os.environ.get('PATH', '')}",
        "OPENSHIELD_DATABASE_URL": "postgresql://openshield:test@localhost/openshield",
        **extra,
    }


def test_backup_publishes_unique_verified_file_with_restrictive_permissions(
    tmp_path: Path,
) -> None:
    bindir, _ = _fake_postgres_tools(tmp_path)
    backup_dir = tmp_path / "backups"
    result = subprocess.run(
        ["sh", str(ROOT / "scripts" / "backup.sh"), str(backup_dir)],
        env=_env(tmp_path, bindir),
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    backups = list(backup_dir.glob("openshield-*.dump"))
    assert len(backups) == 1
    assert backups[0].stat().st_mode & 0o777 == 0o600
    assert backups[0].read_text(encoding="utf-8") == "fake PostgreSQL dump\\n"
    assert not list(backup_dir.glob(".openshield-*"))


def test_backup_removes_partial_artifact_when_dump_fails(tmp_path: Path) -> None:
    bindir, _ = _fake_postgres_tools(tmp_path)
    _command(
        bindir / "pg_dump",
        """
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--file" ]; then
    printf 'partial' > "$2"
    exit 23
  fi
  shift
done
exit 24
""",
    )
    backup_dir = tmp_path / "backups"
    result = subprocess.run(
        ["sh", str(ROOT / "scripts" / "backup.sh"), str(backup_dir)],
        env=_env(tmp_path, bindir),
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 23
    assert not list(backup_dir.glob("openshield-*.dump"))
    assert not list(backup_dir.glob(".openshield-*"))


def test_restore_refuses_non_empty_database_before_running_pg_restore(
    tmp_path: Path,
) -> None:
    bindir, _ = _fake_postgres_tools(tmp_path, target_empty="f")
    backup_file = tmp_path / "backup.dump"
    backup_file.write_text("dump", encoding="utf-8")
    log = tmp_path / "restore.log"
    result = subprocess.run(
        ["sh", str(ROOT / "scripts" / "restore.sh"), str(backup_file)],
        env=_env(
            tmp_path, bindir,
            OPENSHIELD_RESTORE_CONFIRM="YES",
            RESTORE_TARGET_EMPTY="f",
            RESTORE_LOG=str(log),
        ),
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "target database is not empty" in result.stderr
    assert not log.exists()


def test_restore_proceeds_only_when_target_is_empty(tmp_path: Path) -> None:
    bindir, _ = _fake_postgres_tools(tmp_path)
    backup_file = tmp_path / "backup.dump"
    backup_file.write_text("dump", encoding="utf-8")
    log = tmp_path / "restore.log"
    result = subprocess.run(
        ["sh", str(ROOT / "scripts" / "restore.sh"), str(backup_file)],
        env=_env(
            tmp_path, bindir,
            OPENSHIELD_RESTORE_CONFIRM="YES",
            RESTORE_TARGET_EMPTY="t",
            RESTORE_LOG=str(log),
        ),
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "Restore completed" in result.stdout
    assert log.read_text(encoding="utf-8") == "restore-called\\n"


def test_restore_requires_explicit_confirmation(tmp_path: Path) -> None:
    bindir, _ = _fake_postgres_tools(tmp_path)
    backup_file = tmp_path / "backup.dump"
    backup_file.write_text("dump", encoding="utf-8")
    log = tmp_path / "restore.log"
    result = subprocess.run(
        ["sh", str(ROOT / "scripts" / "restore.sh"), str(backup_file)],
        env=_env(
            tmp_path, bindir,
            RESTORE_TARGET_EMPTY="t",
            RESTORE_LOG=str(log),
        ),
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "fresh, empty database" in result.stderr
    assert not log.exists()
