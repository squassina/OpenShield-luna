#!/bin/sh
set -eu
umask 077

: "${OPENSHIELD_DATABASE_URL:?Set OPENSHIELD_DATABASE_URL to the target PostgreSQL database URL}"
BACKUP_DIR="${1:-./backups}"
mkdir -p "$BACKUP_DIR"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
temporary_file=""

cleanup() {
  if [ -n "$temporary_file" ]; then
    rm -f "$temporary_file"
  fi
}
trap cleanup EXIT HUP INT TERM

temporary_file="$(mktemp "$BACKUP_DIR/.openshield-backup.XXXXXX")"
temporary_name="${temporary_file##*/}"
random_suffix="${temporary_name#.openshield-backup.}"
backup_file="$BACKUP_DIR/openshield-$timestamp-$random_suffix.dump"

pg_dump --format=custom --no-owner --no-acl --file "$temporary_file" "$OPENSHIELD_DATABASE_URL"
if ! pg_restore --list "$temporary_file" >/dev/null; then
  echo "Backup verification failed; incomplete file removed." >&2
  exit 1
fi

chmod 600 "$temporary_file"
mv "$temporary_file" "$backup_file"
temporary_file=""
printf 'Verified backup: %s\n' "$backup_file"
