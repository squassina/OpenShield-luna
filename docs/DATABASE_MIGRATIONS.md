# PostgreSQL schema migrations

OpenShield applies schema migrations automatically when the Node opens its PostgreSQL
store. Migrations run in a single transaction while holding a PostgreSQL
transaction-scoped advisory lock, so concurrent Node processes cannot apply the
same migration simultaneously.

The `schema_migrations` table records the applied version, migration name and
timestamp. A migration is committed together with its version record; if any
statement fails, PostgreSQL rolls the transaction back and the migration remains
eligible for retry on the next startup.

The Node acquires its dedicated session-level process advisory lock before
opening the store. This prevents a second Node process from running schema
migrations while another Node instance is active; the transaction-scoped
migration lock additionally serializes schema upgrades themselves.

## Existing installations

The first migration is the idempotent baseline schema already used by previous
OpenShield releases. On an existing database without migration history, OpenShield
creates `schema_migrations`, runs the baseline `CREATE TABLE/INDEX IF NOT EXISTS`
statements, and records version 1. Existing rows and persistent volumes are not
deleted or recreated.

Migration version 2 adds `events.occurred_at TIMESTAMPTZ`, backfills it from
the event payload (falling back to `received_at` for invalid legacy values), and
replaces the standalone event-type index with a composite event-type/occurrence-time
index. New event writes populate the typed column directly; privacy analytics use
typed timestamp predicates instead of casting JSONB values.

Migration version 3 adds an index on `threat_intel_cache.expires_at`.
The background expiration worker removes expired cache entries in batches of at
most 500 rows using row locks with `SKIP LOCKED`; concurrent refreshes are not
deleted, and cleanup counts are logged when rows are removed.

Do not delete the PostgreSQL volume to upgrade the schema. Back up the database
using the normal PostgreSQL backup procedure before upgrading production systems.

## Adding a migration

Add a new ordered entry to the `migrations` sequence in
`PostgresStore.ensure_schema()`:

- Use the next integer version and a descriptive name.
- Keep the statements deterministic and safe to retry after transaction rollback.
- Include forward-compatible data handling for populated tables.
- Add tests for fresh installation, upgrade from the previous version, preserved
  data, and failure/rollback behavior.
- Never edit an already released migration; add a new version instead.

The application refuses to start against a database version newer than the
migration set it supports. Downgrades therefore require an application version
that understands the database schema; migrations are not automatically reversed.
