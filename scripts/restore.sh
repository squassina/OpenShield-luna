#!/bin/sh
set -eu

: "${OPENSHIELD_DATABASE_URL:?Set OPENSHIELD_DATABASE_URL to the target PostgreSQL database URL}"
BACKUP_FILE="${1:?Usage: OPENSHIELD_RESTORE_CONFIRM=YES sh scripts/restore.sh BACKUP.dump}"
if [ ! -f "$BACKUP_FILE" ]; then
  echo "Backup file not found: $BACKUP_FILE" >&2
  exit 1
fi
if [ "${OPENSHIELD_RESTORE_CONFIRM:-}" != "YES" ]; then
  echo "Restore writes into the target database. Use a fresh, empty database and set OPENSHIELD_RESTORE_CONFIRM=YES." >&2
  exit 1
fi
if ! command -v psql >/dev/null 2>&1; then
  echo "psql is required to verify that the restore target is empty." >&2
  exit 1
fi

pg_restore --list "$BACKUP_FILE" >/dev/null

EMPTY_TARGET_SQL="
SELECT NOT (
  EXISTS (
    SELECT 1
    FROM pg_catalog.pg_class AS c
    JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
      AND n.nspname NOT LIKE 'pg_toast%'
      AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
  )
  OR EXISTS (
    SELECT 1
    FROM pg_catalog.pg_proc AS p
    JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
      AND n.nspname NOT LIKE 'pg_toast%'
  )
  OR EXISTS (
    SELECT 1
    FROM pg_catalog.pg_type AS t
    JOIN pg_catalog.pg_namespace AS n ON n.oid = t.typnamespace
    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
      AND n.nspname NOT LIKE 'pg_toast%'
      AND t.typtype IN ('c', 'd', 'e', 'm', 'r')
      AND t.typrelid = 0
  )
  OR EXISTS (
    SELECT 1
    FROM pg_catalog.pg_namespace
    WHERE nspname NOT IN ('pg_catalog', 'information_schema', 'public')
      AND nspname NOT LIKE 'pg_toast%'
  )
  OR EXISTS (SELECT 1 FROM pg_catalog.pg_largeobject_metadata)
)
"
target_is_empty="$(psql -X -v ON_ERROR_STOP=1 -A -t -q --dbname "$OPENSHIELD_DATABASE_URL" -c "$EMPTY_TARGET_SQL")"
case "$target_is_empty" in
  t|true|1) ;;
  *)
    echo "Restore refused: target database is not empty. Create a fresh empty database and retry." >&2
    exit 1
    ;;
esac

pg_restore --exit-on-error --no-owner --no-privileges --dbname "$OPENSHIELD_DATABASE_URL" "$BACKUP_FILE"
printf 'Restore completed from: %s\n' "$BACKUP_FILE"
