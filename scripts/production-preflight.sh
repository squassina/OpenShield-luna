#!/bin/sh
set -eu

fail() {
  echo "Production preflight failed: $1" >&2
  exit 1
}

password="${OPENSHIELD_POSTGRES_PASSWORD:-}"
database_url="${OPENSHIELD_DATABASE_URL:-}"
publish_address="${OPENSHIELD_PUBLISH_ADDRESS:-127.0.0.1}"

case "$password" in
  ""|openshield-dev-password|replace-with-a-local-db-password)
    fail "set OPENSHIELD_POSTGRES_PASSWORD to a unique secret"
    ;;
esac
case "$password" in
  *[!A-Za-z0-9_-]*)
    fail "PostgreSQL password must use URL-safe characters: letters, digits, '_' or '-'"
    ;;
esac
if [ "${#password}" -lt 24 ]; then
  fail "PostgreSQL password must contain at least 24 characters"
fi

expected_database_url="postgresql://openshield:$password@openshield-db:5432/openshield"
if [ "$database_url" != "$expected_database_url" ]; then
  fail "OPENSHIELD_DATABASE_URL must match the Compose PostgreSQL credentials and service"
fi

case "$publish_address" in
  0.0.0.0|::|\[::\]|0:0:0:0:0:0:0:0)
    fail "do not publish the Node API on a wildcard address; bind loopback or a trusted LAN IP"
    ;;
esac

printf 'Production preflight passed (PostgreSQL password configured; API bind: %s).\n' "$publish_address"
