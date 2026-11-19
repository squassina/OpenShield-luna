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

pg_restore --list "$BACKUP_FILE" >/dev/null

target_has_objects="$(
  psql --no-psqlrc --quiet --tuples-only --no-align \
    --set ON_ERROR_STOP=1 \
    --dbname "$OPENSHIELD_DATABASE_URL" \
    --command "
      SELECT
        EXISTS (
          SELECT 1
          FROM pg_catalog.pg_class AS relation
          JOIN pg_catalog.pg_namespace AS namespace
            ON namespace.oid = relation.relnamespace
          WHERE namespace.nspname NOT IN ('pg_catalog', 'information_schema')
            AND namespace.nspname NOT LIKE 'pg_toast%'
        )
        OR EXISTS (
          SELECT 1
          FROM pg_catalog.pg_proc AS routine
          JOIN pg_catalog.pg_namespace AS namespace
            ON namespace.oid = routine.pronamespace
          WHERE namespace.nspname NOT IN ('pg_catalog', 'information_schema')
            AND namespace.nspname NOT LIKE 'pg_toast%'
        )
        OR EXISTS (
          SELECT 1
          FROM pg_catalog.pg_type AS user_type
          JOIN pg_catalog.pg_namespace AS namespace
            ON namespace.oid = user_type.typnamespace
          WHERE namespace.nspname NOT IN ('pg_catalog', 'information_schema')
            AND namespace.nspname NOT LIKE 'pg_toast%'
        )
        OR EXISTS (
          SELECT 1
          FROM pg_catalog.pg_namespace
          WHERE nspname NOT IN ('pg_catalog', 'information_schema', 'public')
            AND nspname NOT LIKE 'pg_toast%'
        )
    "
)"

case "$target_has_objects" in
  f)
    ;;
  t)
    echo "Restore refused: target database is not empty. Use a newly created, empty database." >&2
    exit 1
    ;;
  *)
    echo "Restore refused: could not verify that the target database is empty." >&2
    exit 1
    ;;
esac

pg_restore --single-transaction --exit-on-error --no-owner --no-privileges \
  --dbname "$OPENSHIELD_DATABASE_URL" "$BACKUP_FILE"
printf 'Restore completed from: %s\n' "$BACKUP_FILE"
