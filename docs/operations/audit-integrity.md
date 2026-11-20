# Audit integrity and operational limitations

OpenShield stores audit records in PostgreSQL. Schema migration version 4 adds a
SHA-256 hash chain and a persisted chain-head row.

## Integrity model

Each audit record stores:

- `previous_hash`: the SHA-256 digest of the preceding audit record (or the
  all-zero genesis digest for the first record).
- `record_hash`: SHA-256 of a canonical JSON representation containing the
  format version, audit ID, UTC occurrence timestamp, actor, action, target,
  details, and `previous_hash`.

Audit inserts serialize on the singleton `audit_chain_state` row. The audit
row and new chain head are written in the same PostgreSQL transaction as the
business operation that generated the audit record. A rollback therefore
rolls back both the operation and its audit row/head update.

The migration backfills existing records in ascending `audit_id` order and
refuses a non-genesis or partially hashed starting state. It does not delete or
rewrite the business meaning of legacy records. Database triggers reject
invalid predecessor inserts, atomically advance the chain head after every
insert, and reject UPDATE, DELETE, and TRUNCATE against
`audit_records` during normal operation. The test-only `PostgresStore.reset()`
temporarily disables user triggers with database-owner privileges, truncates
test state, and re-enables the triggers in the same transaction. No session
variable or caller-controlled GUC bypass is accepted by the audit guards.

## Verify the chain

Call the read-only endpoint:

~~~bash
curl --fail http://localhost:8000/api/v1/audit/integrity
~~~

A valid response includes `valid: true`, the number of checked records, the
last audit ID, and the computed and stored head hashes. An invalid response
sets `valid: false` and returns a bounded error code such as
`previous_hash_mismatch`, `record_hash_mismatch`, or
`chain_head_mismatch`. It does not return record details or secrets.

The audit list at `GET /api/v1/audit` also includes each row's predecessor and
record hash so an independent verifier can reproduce a page's hashes. The list
endpoint is bounded to 500 records per request.

## Security boundary

The hash chain detects accidental edits, isolated row modifications, row
reordering, and chain-head inconsistencies. Database triggers prevent ordinary
application code from updating/deleting/truncating audit rows or inserting a
record with a predecessor that does not match the current chain head.

This is **not** a digital signature, trusted timestamp, or external immutable
anchor. A PostgreSQL administrator with sufficient privileges can disable or
replace triggers, rewrite records, and recompute the chain head. A database
backup under the same administrative control is not independent proof of
integrity. Do not present this local chain alone as compliance-grade or
non-repudiation evidence.

For stronger evidence, export verified records and their chain head to an
independent immutable/WORM destination controlled separately from the Node and
PostgreSQL administrators. OpenShield provides a verified NDJSON export and an
AWS S3 Object Lock COMPLIANCE uploader; see
[external WORM anchoring](audit-worm-anchoring.md). The first deployment-specific
upload and bucket access review must still be completed before claiming an
external anchor is active.

## Retention and archival

No automatic audit retention or deletion is enabled. The approved retention
period, legal hold rules, archive cadence, access controls, and deletion
authority have not been defined. Do not delete rows from `audit_records`
manually; doing so breaks the chain and is blocked by the database trigger.

A future archival design must verify and export a complete prefix, publish its
head hash to an independent immutable destination, and define how a retained
chain starts from the externally anchored checkpoint. Do not implement
time-based DELETE without those requirements and a reviewed recovery plan.

## Backup and restore

Include `audit_records`, `audit_chain_state`, trigger functions, and
`schema_migrations` in normal PostgreSQL backups. After restore, verify
`GET /api/v1/audit/integrity` before treating the audit log as usable. Keep
the backup and any future WORM export under separate administrative controls.
