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

Migration version 4 adds `previous_hash` and `record_hash` to `audit_records`
and creates the singleton `audit_chain_state` head. Existing rows are backfilled
in ascending `audit_id` order inside the migration transaction using canonical
JSON and SHA-256. The migration fails closed if the chain state is not at its
expected genesis value or legacy rows contain partial hashes. It then installs
triggers that reject invalid predecessor inserts and UPDATE, DELETE, or TRUNCATE
against audit records during normal operation. The test-only store reset sets a
transaction-local flag before truncating and reseeding the chain.

Every audit insert locks the chain-head row, allocates the next audit ID, hashes
the record with its predecessor hash, inserts the complete row, and updates
the head in the same transaction. `GET /api/v1/audit/integrity` verifies the
record hashes, predecessor links, and persisted head.

The local hash chain detects row edits, reordering, and accidental application
mutation. It is not a digital signature or external trust anchor: a privileged
database administrator able to alter the rows, triggers, and head can recompute
the chain. External immutable/WORM export and a retention/archival policy remain
separate operational requirements. No automatic audit retention or deletion
is enabled.

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
