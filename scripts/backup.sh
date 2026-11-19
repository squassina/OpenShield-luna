#!/bin/sh
set -eu
umask 077

: "${OPENSHIELD_DATABASE_URL:?Set OPENSHIELD_DATABASE_URL to the target PostgreSQL database URL}"
BACKUP_DIR="${1:-./backups}"
mkdir -p "$BACKUP_DIR"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
temp_file="$(mktemp "$BACKUP_DIR/.openshield-$timestamp.XXXXXX")"

cleanup() {
  if [ -n "${temp_file:-}" ]; then
    rm -f "$temp_file"
  fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

pg_dump --format=custom --no-owner --no-acl --file "$temp_file" "$OPENSHIELD_DATABASE_URL"
if ! pg_restore --list "$temp_file" >/dev/null; then
  echo "Backup verification failed; incomplete file removed." >&2
  exit 1
fi
chmod 600 "$temp_file"

suffix="${temp_file##*.}"
backup_file="$BACKUP_DIR/openshield-$timestamp-$suffix.dump"
# Hard-link publication is atomic and fails rather than overwriting an existing backup.
ln "$temp_file" "$backup_file"
rm -f "$temp_file"
temp_file=""
printf 'Verified backup: %s\n' "$backup_file"
