#!/bin/sh
set -eu
umask 077

: "\${OPENSHIELD_DATABASE_URL:?Set OPENSHIELD_DATABASE_URL to the target PostgreSQL database URL}"
BACKUP_DIR="\${1:-./backups}"
mkdir -p "$BACKUP_DIR"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
temporary_file="$(mktemp "$BACKUP_DIR/.openshield-$timestamp.XXXXXX")"
unique_suffix="\${temporary_file##*.}"
backup_file="$BACKUP_DIR/openshield-$timestamp-$unique_suffix.dump"

trap 'rm -f "$temporary_file"' EXIT
trap 'exit 1' HUP INT TERM

pg_dump --format=custom --no-owner --no-acl --file "$temporary_file" "$OPENSHIELD_DATABASE_URL"
pg_restore --list "$temporary_file" >/dev/null
chmod 600 "$temporary_file"
mv "$temporary_file" "$backup_file"
trap - EXIT HUP INT TERM
printf 'Verified backup: %s\n' "$backup_file"
