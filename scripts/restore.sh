#!/bin/sh
set -eu

: "\${OPENSHIELD_DATABASE_URL:?Set OPENSHIELD_DATABASE_URL to the target PostgreSQL database URL}"
BACKUP_FILE="\${1:?Usage: OPENSHIELD_RESTORE_CONFIRM=YES sh scripts/restore.sh BACKUP.dump}"
if [ ! -f "$BACKUP_FILE" ]; then
  echo "Backup file not found: $BACKUP_FILE" >&2
  exit 1
fi
if [ "\${OPENSHIELD_RESTORE_CONFIRM:-}" != "YES" ]; then
  echo "Restore writes into the target database. Use a fresh, empty database and set OPENSHIELD_RESTORE_CONFIRM=YES." >&2
  exit 1
fi

pg_restore --list "$BACKUP_FILE" >/dev/null

target_database="$(psql "$OPENSHIELD_DATABASE_URL" -X -A -t -v ON_ERROR_STOP=1 -c 'SELECT current_database()')"
case "$target_database" in
  ""|postgres|template0|template1)
    echo "Refusing restore into an empty or system database name: $target_database" >&2
    exit 1
    ;;
esac

object_count="$(psql "$OPENSHIELD_DATABASE_URL" -X -A -t -v ON_ERROR_STOP=1 -c "
SELECT COUNT(*)
FROM (
    SELECT 1
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS schema
      ON schema.oid = relation.relnamespace
    WHERE schema.nspname NOT IN ('pg_catalog', 'information_schema')
      AND schema.nspname NOT LIKE 'pg_toast%'
      AND relation.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
    UNION ALL
    SELECT 1
    FROM pg_catalog.pg_proc AS routine
    JOIN pg_catalog.pg_namespace AS schema
      ON schema.oid = routine.pronamespace
    WHERE schema.nspname NOT IN ('pg_catalog', 'information_schema')
    UNION ALL
    SELECT 1
    FROM pg_catalog.pg_type AS custom_type
    JOIN pg_catalog.pg_namespace AS schema
      ON schema.oid = custom_type.typnamespace
    WHERE schema.nspname NOT IN ('pg_catalog', 'information_schema')
      AND custom_type.typtype IN ('d', 'e', 'r')
    UNION ALL
    SELECT 1
    FROM pg_catalog.pg_namespace
    WHERE nspname NOT IN ('pg_catalog', 'information_schema', 'public')
      AND nspname NOT LIKE 'pg_toast%'
    UNION ALL
    SELECT 1 FROM pg_catalog.pg_extension WHERE extname <> 'plpgsql'
    UNION ALL
    SELECT 1 FROM pg_catalog.pg_largeobject_metadata
) AS existing_objects
")"

case "$object_count" in
  0)
    ;;
  ""|*[!0-9]*)
    echo "Could not verify that the target database is empty; refusing restore." >&2
    exit 1
    ;;
  *)
    echo "Target database '$target_database' contains $object_count user objects; restore requires an empty database." >&2
    exit 1
    ;;
esac

pg_restore --exit-on-error --no-owner --no-privileges --dbname "$OPENSHIELD_DATABASE_URL" "$BACKUP_FILE"
printf 'Restore completed from: %s\n' "$BACKUP_FILE"
