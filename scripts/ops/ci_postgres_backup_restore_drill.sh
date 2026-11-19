#!/bin/sh
set -eu

if [ "${GITHUB_ACTIONS:-}" != "true" ]; then
  echo "This disposable-database drill is restricted to GitHub Actions." >&2
  exit 2
fi

DB_USER="openshield"
RUN_SUFFIX="${GITHUB_RUN_ID:-0}-${GITHUB_RUN_ATTEMPT:-1}-$$"
SOURCE_DB="openshield_ci_restore_source_${RUN_SUFFIX}"
TARGET_DB="openshield_ci_restore_target_${RUN_SUFFIX}"
REPORT_DIR="$(mktemp -d)"
CONTAINER_WORK_DIR="/tmp/openshield-ci-restore-${RUN_SUFFIX}"
BACKUP_SCRIPT_IN_CONTAINER="$CONTAINER_WORK_DIR/backup.sh"
RESTORE_SCRIPT_IN_CONTAINER="$CONTAINER_WORK_DIR/restore.sh"
CONTAINER_BACKUP_DIR="$CONTAINER_WORK_DIR/backups"

cleanup() {
  docker compose exec -T openshield-db dropdb --if-exists --force \
    -U "$DB_USER" "$TARGET_DB" >/dev/null 2>&1 || true
  docker compose exec -T openshield-db dropdb --if-exists --force \
    -U "$DB_USER" "$SOURCE_DB" >/dev/null 2>&1 || true
  docker compose exec -T openshield-db rm -rf "$CONTAINER_WORK_DIR" \
    >/dev/null 2>&1 || true
  rm -rf "$REPORT_DIR"
}
trap cleanup EXIT

POSTGRES_PASSWORD="$(
  docker compose config --format json |
    python -c 'import json, sys; print(json.load(sys.stdin)["services"]["openshield-db"]["environment"]["POSTGRES_PASSWORD"])'
)"
DATABASE_URL() {
  DATABASE_NAME="$1" DATABASE_HOST="$2" POSTGRES_PASSWORD="$POSTGRES_PASSWORD" python -c '
import os
from urllib.parse import quote
password = quote(os.environ["POSTGRES_PASSWORD"], safe="")
database = quote(os.environ["DATABASE_NAME"], safe="")
host = os.environ["DATABASE_HOST"]
print(f"postgresql://openshield:{password}@{host}:5432/{database}")
'
}

SOURCE_DB_URL="$(DATABASE_URL "$SOURCE_DB" 127.0.0.1)"
SOURCE_TEST_URL="$(DATABASE_URL "$SOURCE_DB" openshield-db)"
TARGET_DB_URL="$(DATABASE_URL "$TARGET_DB" 127.0.0.1)"
TARGET_TEST_URL="$(DATABASE_URL "$TARGET_DB" openshield-db)"

docker compose exec -T openshield-db createdb -U "$DB_USER" "$SOURCE_DB"
docker compose exec -T openshield-db psql -v ON_ERROR_STOP=1 -U "$DB_USER" -d "$SOURCE_DB" <<'SQL'
CREATE TABLE public.schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL
);
INSERT INTO public.schema_migrations (version, name) VALUES
    (1, 'initial schema'),
    (2, 'typed event occurrence timestamps'),
    (3, 'threat intelligence cache expiry index');

CREATE TABLE public.backup_restore_fixture (
    fixture_id BIGINT PRIMARY KEY,
    payload JSONB NOT NULL
);
INSERT INTO public.backup_restore_fixture (fixture_id, payload) VALUES
    (1, '{"kind":"event","severity":"low"}'),
    (2, '{"kind":"event","severity":"high"}'),
    (3, '{"kind":"integration","enabled":true}');
SQL

docker compose run --rm --no-deps \
  -e "OPENSHIELD_DATABASE_URL=$SOURCE_TEST_URL" \
  -v "$REPORT_DIR:/reports" \
  openshield-test python scripts/ops/verify_database_restore.py \
  --statement-timeout-ms 30000 capture --output /reports/source-manifest.json

docker compose exec -T openshield-db mkdir -p "$CONTAINER_WORK_DIR"
docker compose cp scripts/backup.sh "openshield-db:$BACKUP_SCRIPT_IN_CONTAINER"
docker compose cp scripts/restore.sh "openshield-db:$RESTORE_SCRIPT_IN_CONTAINER"

docker compose exec -T openshield-db env \
  OPENSHIELD_DATABASE_URL="$SOURCE_DB_URL" \
  sh "$BACKUP_SCRIPT_IN_CONTAINER" "$CONTAINER_BACKUP_DIR"

BACKUP_PATH="$(docker compose exec -T openshield-db sh -c \
  'set -- "$1"/openshield-*.dump; [ -f "$1" ] && printf "%s\\n" "$1"' \
  sh "$CONTAINER_BACKUP_DIR")"
test -n "$BACKUP_PATH"

docker compose exec -T openshield-db createdb -U "$DB_USER" "$TARGET_DB"
docker compose exec -T openshield-db env \
  OPENSHIELD_DATABASE_URL="$TARGET_DB_URL" \
  OPENSHIELD_RESTORE_CONFIRM=YES \
  sh "$RESTORE_SCRIPT_IN_CONTAINER" "$BACKUP_PATH"

docker compose run --rm --no-deps \
  -e "OPENSHIELD_DATABASE_URL=$TARGET_TEST_URL" \
  -v "$REPORT_DIR:/reports" \
  openshield-test python scripts/ops/verify_database_restore.py \
  --statement-timeout-ms 30000 verify --manifest /reports/source-manifest.json

echo "PostgreSQL backup/restore drill passed: isolated source and target databases matched."
