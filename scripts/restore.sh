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
pg_restore --exit-on-error --no-owner --no-privileges --dbname "$OPENSHIELD_DATABASE_URL" "$BACKUP_FILE"
printf 'Restore completed from: %s\n' "$BACKUP_FILE"
