# Event load, query plans and backup/restore — Phase 1C

Tracks [Issue #19](https://github.com/squassina/OpenShield-luna/issues/19).

The repository provides keyset pagination and opt-in event retention. Retention is disabled by default. This procedure measures the deployed database and verifies recovery without enabling destructive retention.

## 1. Preconditions

- Use staging or a maintenance window.
- Take a verified backup before load tests.
- Register a dedicated Suricata or Zeek integration for synthetic traffic.
- Benchmark only the selected integration ID.
- Start with 1,000 events and batch size 100. Increase only after reviewing resource use.
- Do not load-test production traffic without an explicit budget.

## 2. Ingestion benchmark

From repository root:

~~~bash
python scripts/ops/benchmark_sensor_ingestion.py \
  --base-url http://localhost:8000 \
  --integration-id benchmark-zeek \
  --kind zeek \
  --events 1000 \
  --batch-size 100
~~~

For Suricata, use --kind suricata. The integration must already exist and be enabled. The script sends sequential requests, verifies accepted/duplicate counts, measures latency and throughput, then reads ingested events through cursor pagination.

Optional HTTP Basic credentials are read from OPENSHIELD_BENCHMARK_USERNAME and OPENSHIELD_BENCHMARK_PASSWORD. Never put credentials in command-line arguments.

Run progressively (1k, 10k, 50k). Stop if API latency, DB load, disk growth or sensor backlog exceeds the deployment's budget. Record host resources, DB volume size and image/commit. Synthetic RFC 5737 addresses are used; this is not representative network topology.

## 3. Query plans and table sizes

Generate a machine-readable report from the dev tools image. The command connects to the configured database in read-only mode, reports estimated event row counts/table and index sizes, index usage statistics, and plans for the same filters and ordering used by the event-list API:

~~~bash
docker compose run --rm openshield-test python scripts/ops/inspect_event_storage.py \
  --integration-id benchmark-zeek \
  --event-type network.zeek.conn \
  --severity info > event-storage-report.json
~~~

The default uses EXPLAIN without executing the SELECT statements. n_live_tup and n_dead_tup are PostgreSQL estimates; index counters are cumulative since the last statistics reset. Preserve the JSON report with the benchmark run's commit, database version and host details.

For measured execution time and buffer usage, repeat on staging only with **--analyze**. This enables EXPLAIN (ANALYZE, BUFFERS), which executes each SELECT and can add real database load. The utility applies a read-only transaction and a bounded statement timeout (30 seconds by default).

The equivalent manual inventory queries remain available:

~~~bash
docker compose exec -T openshield-db psql -U openshield -d openshield -c "SELECT version();"
docker compose exec -T openshield-db psql -U openshield -d openshield -c "SELECT relname, n_live_tup, pg_total_relation_size(relid) AS bytes FROM pg_stat_user_tables ORDER BY pg_total_relation_size(relid) DESC;"
~~~

Do not add partitioning or indexes by intuition. Change schema only when measurements show a repeatable bottleneck; include representative data and regression tests.

## 4. PostgreSQL backup

Use the repository backup script to create a verified custom-format archive:

~~~bash
OPENSHIELD_DATABASE_URL="$OPENSHIELD_DATABASE_URL" sh scripts/backup.sh ./backups
~~~

The script writes to a unique temporary file in the destination directory, validates the archive with `pg_restore --list`, applies mode 0600, then atomically renames it to the published `openshield-*.dump` filename. A failed dump or archive validation removes the incomplete temporary file. The random suffix avoids collisions between backups created in the same second.

For a row-count restore drill, follow Section 5 and stop database writers before capturing both the manifest and backup. The CI workflow also executes these exact backup and restore scripts against disposable PostgreSQL databases.

Store backups outside the Docker volume and encrypt at rest. Dumps contain network metadata, host identifiers, integration configuration and audit history. Treat as sensitive household/business data.

## 5. Restore drill into a separate database

Never overwrite the live database during acceptance. Use staging, stop Node and any other database writers, and keep the source database unchanged until the manifest and backup are captured. The manifest uses exact table counts from one repeatable-read, read-only snapshot. Counts will not match a backup if application writes continue between manifest capture and pg_dump.

Capture the manifest and backup while writers remain stopped:

~~~bash
mkdir -p backups
docker compose stop openshield-node
trap 'docker compose start openshield-node' EXIT

docker compose run --rm -v "$PWD/backups:/reports" openshield-test \
  python scripts/ops/verify_database_restore.py \
  --statement-timeout-ms 120000 capture \
  --output /reports/source-manifest.json

RUN_SUFFIX="$(date -u +%Y%m%dT%H%M%SZ)-$$"
BACKUP_SCRIPT_IN_CONTAINER="/tmp/openshield-backup-$RUN_SUFFIX.sh"
CONTAINER_BACKUP_DIR="/tmp/openshield-backups-$RUN_SUFFIX"
docker compose cp scripts/backup.sh "openshield-db:$BACKUP_SCRIPT_IN_CONTAINER"
docker compose exec -T openshield-db mkdir -p "$CONTAINER_BACKUP_DIR"
docker compose exec -T openshield-db env \
  OPENSHIELD_DATABASE_URL="dbname=openshield user=openshield" \
  sh "$BACKUP_SCRIPT_IN_CONTAINER" "$CONTAINER_BACKUP_DIR"

BACKUP_PATH="$(docker compose exec -T openshield-db sh -c \
  'set -- "$1"/openshield-*.dump; [ -f "$1" ] && printf "%s\\n" "$1"' \
  sh "$CONTAINER_BACKUP_DIR")"
BACKUP_FILE="backups/${BACKUP_PATH##*/}"
docker compose cp "openshield-db:$BACKUP_PATH" "$BACKUP_FILE"
~~~

The manifest contains database/version metadata, schema migration names/versions and exact row counts for all public base tables. It contains no event payloads, credentials, host identifiers or other row contents. The verifier creates the manifest atomically with mode 0600.

Create a fresh restore target; do not drop or truncate anything:

~~~bash
docker compose exec -T openshield-db createdb \
  -U openshield openshield_restore_test

RESTORE_SCRIPT_IN_CONTAINER="/tmp/openshield-restore-$RUN_SUFFIX.sh"
RESTORE_ARCHIVE_IN_CONTAINER="/tmp/openshield-restore-$RUN_SUFFIX.dump"
docker compose cp scripts/restore.sh "openshield-db:$RESTORE_SCRIPT_IN_CONTAINER"
docker compose cp "$BACKUP_FILE" "openshield-db:$RESTORE_ARCHIVE_IN_CONTAINER"

docker compose exec -T openshield-db env \
  OPENSHIELD_DATABASE_URL="dbname=openshield_restore_test user=openshield" \
  OPENSHIELD_RESTORE_CONFIRM=YES \
  sh "$RESTORE_SCRIPT_IN_CONTAINER" "$RESTORE_ARCHIVE_IN_CONTAINER"
~~~

Point the verifier at the separate target database. Set the URL through the deployment's secret mechanism; URL-encode special characters in credentials:

~~~bash
export RESTORE_DATABASE_URL='postgresql://openshield:<password>@openshield-db:5432/openshield_restore_test'

OPENSHIELD_DATABASE_URL="$RESTORE_DATABASE_URL" docker compose run --rm \
  -e OPENSHIELD_DATABASE_URL \
  -v "$PWD/backups:/reports" openshield-test \
  python scripts/ops/verify_database_restore.py \
  --statement-timeout-ms 120000 verify \
  --manifest /reports/source-manifest.json
~~~

The verifier exits non-zero when the target has the same database name as the source, a different PostgreSQL major version, different migration history, missing/extra public tables, or any row-count mismatch. It uses a repeatable-read, read-only snapshot and per-statement timeout. Counting every table reads the tables and may take time on a large database; raise the timeout only after reviewing staging load.

The restore script requires `OPENSHIELD_RESTORE_CONFIRM=YES`, validates the archive first, and invokes `pg_restore --single-transaction --exit-on-error`. A failed restore is rolled back by PostgreSQL instead of leaving a partially restored target.

CI also runs a real backup/restore round-trip between disposable PostgreSQL databases and compares the restored database with the source manifest. This validates the actual repository scripts and verifier against a real PostgreSQL server; it does not replace a staging restore drill on the deployment's actual data volume.

After a successful comparison, validate application readiness and key workflows against the restored database in an isolated deployment. Record backup size/time, restore time, verifier JSON output and the tested image/commit. Treat the backup as sensitive data and encrypt it at rest. Keep the original Node database URL unchanged when the shell trap starts Node again.

After retaining the evidence, remove only the uniquely named temporary databases and container files from this drill. Do not drop the live database or delete persistent Docker volumes. Do not put the real password in shell history; use a protected .pgpass or equivalent secret mechanism.

## 6. Results

| Measurement | Run 1 | Run 2 | Run 3 |
|---|---:|---:|---:|
| Event count / batch size | | | |
| Ingested events/sec | | | |
| p50 / p95 / p99 request latency | | | |
| Read pagination events/sec | | | |
| PostgreSQL volume before/after | | | |
| CPU / memory peak | | | |
| Query plan / buffers | | | |
| Backup size / duration | | | |
| Restore duration | | | |
| Restored row-count comparison | | | |

Close Issue #19 only after measured load results, reviewed query plans and a successful isolated restore drill are attached. Keep OPENSHIELD_EVENT_RETENTION_DAYS=0 unless a retention policy is explicitly approved.
