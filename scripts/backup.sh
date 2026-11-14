#!/bin/sh
set -eu
umask 077

: "${OPENSHIELD_DATABASE_URL:?Set OPENSHIELD_DATABASE_URL to the target PostgreSQL database URL}"
BACKUP_DIR="${1:-./backups}"
mkdir -p "$BACKUP_DIR"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_file="$BACKUP_DIR/openshield-$timestamp.dump"

pg_dump --format=custom --no-owner --no-acl --file "$backup_file" "$OPENSHIELD_DATABASE_URL"
if ! pg_restore --list "$backup_file" >/dev/null; then
  rm -f "$backup_file"
  echo "Backup verification failed; incomplete file removed." >&2
  exit 1
fi
chmod 600 "$backup_file"
printf 'Verified backup: %s\n' "$backup_file"
