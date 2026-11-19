import os
import subprocess
from pathlib import Path

import pytest

ROOT = next(
    parent
    for parent in Path(__file__).resolve().parents
    if (parent / "scripts" / "restore.sh").is_file()
)


def _executable(directory: Path, name: str, content: str) -> None:
    path = directory / name
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def _run(script: str, *args: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["sh", str(ROOT / "scripts" / script), *args],
        cwd=ROOT,
        env={**os.environ, **env},
        capture_output=True,
        text=True,
        check=False,
    )


def _fake_db_commands(bin_dir: Path, restore_log: Path) -> None:
    _executable(
        bin_dir,
        "psql",
        """#!/bin/sh
case "$*" in
  *current_database*) printf '%s\\\\n' "\${FAKE_DB_NAME:-openshield_restore}" ;;
  *) printf '%s\\\\n' "\${FAKE_DB_OBJECTS:-0}" ;;
esac
""",
    )
    _executable(
        bin_dir,
        "pg_restore",
        f"""#!/bin/sh
printf '%s\\\\n' "$*" >> '{restore_log}'
exit 0
""",
    )


def test_restore_runs_only_when_target_is_a_confirmed_empty_database(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    restore_log = tmp_path / "pg_restore.log"
    _fake_db_commands(bin_dir, restore_log)
    backup = tmp_path / "snapshot.dump"
    backup.write_bytes(b"backup")

    result = _run(
        "restore.sh",
        str(backup),
        env={
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "OPENSHIELD_DATABASE_URL": "postgresql://openshield:secret@db/openshield",
            "OPENSHIELD_RESTORE_CONFIRM": "YES",
        },
    )

    assert result.returncode == 0, result.stderr
    calls = restore_log.read_text(encoding="utf-8").splitlines()
    assert len(calls) == 2
    assert calls[0].startswith("--list ")
    assert "--exit-on-error" in calls[1]


@pytest.mark.parametrize(
    ("database_name", "object_count"),
    [("openshield_restore", "1"), ("postgres", "0"), ("template1", "0")],
)
def test_restore_refuses_nonempty_or_system_database(
    tmp_path: Path,
    database_name: str,
    object_count: str,
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    restore_log = tmp_path / "pg_restore.log"
    _fake_db_commands(bin_dir, restore_log)
    backup = tmp_path / "snapshot.dump"
    backup.write_bytes(b"backup")

    result = _run(
        "restore.sh",
        str(backup),
        env={
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "OPENSHIELD_DATABASE_URL": "postgresql://openshield:secret@db/openshield",
            "OPENSHIELD_RESTORE_CONFIRM": "YES",
            "FAKE_DB_NAME": database_name,
            "FAKE_DB_OBJECTS": object_count,
        },
    )

    assert result.returncode != 0
    assert "requires an empty database" in result.stderr or "system database name" in result.stderr
    calls = restore_log.read_text(encoding="utf-8").splitlines()
    assert len(calls) == 1
    assert calls[0].startswith("--list ")


def test_backup_uses_unique_atomic_artifacts_and_private_permissions(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _executable(bin_dir, "date", "#!/bin/sh\\nprintf '20261119T120000Z\\\\n'\\n")
    _executable(
        bin_dir,
        "pg_dump",
        """#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--file" ]; then
    shift
    printf 'valid dump' > "$1"
    exit "\${FAKE_DUMP_EXIT:-0}"
  fi
  shift
done
exit 2
""",
    )
    _executable(bin_dir, "pg_restore", "#!/bin/sh\\nexit 0\\n")
    output_dir = tmp_path / "backups"
    env = {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "OPENSHIELD_DATABASE_URL": "postgresql://openshield:secret@db/openshield",
    }

    first = _run("backup.sh", str(output_dir), env=env)
    second = _run("backup.sh", str(output_dir), env=env)

    assert first.returncode == second.returncode == 0
    artifacts = sorted(output_dir.glob("*.dump"))
    assert len(artifacts) == 2
    assert artifacts[0].name != artifacts[1].name
    assert all(item.stat().st_mode & 0o777 == 0o600 for item in artifacts)
    assert not list(output_dir.glob(".openshield-*"))


def test_backup_removes_partial_file_when_dump_fails(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _executable(bin_dir, "date", "#!/bin/sh\\nprintf '20261119T120000Z\\\\n'\\n")
    _executable(
        bin_dir,
        "pg_dump",
        """#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--file" ]; then
    shift
    printf 'partial dump' > "$1"
    exit 1
  fi
  shift
done
exit 2
""",
    )
    _executable(bin_dir, "pg_restore", "#!/bin/sh\\nexit 0\\n")
    output_dir = tmp_path / "backups"

    result = _run(
        "backup.sh",
        str(output_dir),
        env={
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "OPENSHIELD_DATABASE_URL": "postgresql://openshield:secret@db/openshield",
        },
    )

    assert result.returncode != 0
    assert list(output_dir.iterdir()) == []


def test_production_preflight_rejects_default_or_short_credentials() -> None:
    for password in ("openshield-dev-password", "too-short"):
        result = _run(
            "production-preflight.sh",
            env={
                "OPENSHIELD_POSTGRES_PASSWORD": password,
                "OPENSHIELD_DATABASE_URL": f"postgresql://openshield:{password}@openshield-db:5432/openshield",
            },
        )
        assert result.returncode != 0


def test_production_preflight_requires_matching_database_url_and_non_wildcard_bind() -> None:
    password = "unique-long-production-password-2026"
    shared = {
        "OPENSHIELD_POSTGRES_PASSWORD": password,
        "OPENSHIELD_DATABASE_URL": f"postgresql://openshield:{password}@openshield-db:5432/openshield",
    }

    assert _run("production-preflight.sh", env=shared).returncode == 0
    assert _run(
        "production-preflight.sh",
        env={**shared, "OPENSHIELD_DATABASE_URL": "postgresql://wrong"},
    ).returncode != 0
    assert _run(
        "production-preflight.sh",
        env={**shared, "OPENSHIELD_PUBLISH_ADDRESS": "0.0.0.0"},
    ).returncode != 0
