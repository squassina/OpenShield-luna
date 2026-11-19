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

Before running the benchmark, issue an integration-scoped sensor credential through `PUT /api/v1/sensors/{integration-id}/credentials` and export the returned token as `OPENSHIELD_BENCHMARK_SENSOR_TOKEN`. The benchmark sends this Bearer token only to the sensor ingestion endpoint. Optional HTTP Basic credentials are read from `OPENSHIELD_BENCHMARK_USERNAME` and `OPENSHIELD_BENCHMARK_PASSWORD` for health/read requests when API authentication is enabled; Basic credentials do not replace the sensor token. Never put credentials in command-line arguments or commit them.

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

Use the repository backup script. The PostgreSQL client tools are already installed in the database container; no host-side `pg_dump` installation is required.

Export the database password through your secret manager (do not type the literal password in shell commands), then create a short-lived working directory in the database container and copy the script into it:

~~~bash
: "${OPENSHIELD_POSTGRES_PASSWORD:?Load the PostgreSQL password from your secret manager}"
export PGPASSWORD="$OPENSHIELD_POSTGRES_PASSWORD"
CONTAINER_WORK_DIR="$(docker compose exec -T openshield-db mktemp -d /tmp/openshield-backup.XXXXXX)"
mkdir -p backups

SOURCE_DATABASE_URL="host=127.0.0.1 port=5432 dbname=openshield user=openshield"

docker compose exec -T openshield-db mkdir -p "$CONTAINER_WORK_DIR"
docker compose cp scripts/backup.sh "openshield-db:$CONTAINER_WORK_DIR/backup.sh"
docker compose exec -T -e PGPASSWORD \
  -e "OPENSHIELD_DATABASE_URL=$SOURCE_DATABASE_URL" \
  openshield-db sh "$CONTAINER_WORK_DIR/backup.sh" "$CONTAINER_WORK_DIR"
~~~

Copy the resulting archive to the host:

~~~bash
BACKUP_PATH="$(docker compose exec -T openshield-db sh -c \
  'set -- "$1"/openshield-*.dump; [ -f "$1" ] && printf "%s\\n" "$1"' \
  sh "$CONTAINER_WORK_DIR")"
BACKUP_FILE="backups/${BACKUP_PATH##*/}"
docker compose cp "openshield-db:$BACKUP_PATH" "$BACKUP_FILE"
~~~

The script writes to a unique temporary file in the destination directory, validates the archive with `pg_restore --list`, applies mode 0600, then atomically renames it to the published `openshield-*.dump` filename. A failed dump or archive validation removes the incomplete temporary file. The random suffix avoids filename collisions even when multiple backups start in the same second.

Store backups outside the Docker volume and encrypt them at rest. Dumps contain network metadata, host identifiers, integration configuration and audit history. Treat them as sensitive household/business data.

## 5. Restore drill into a separate database

Never overwrite the live database during acceptance. Use staging and stop Node plus any other database writers until both the source manifest and backup have been captured. The manifest uses exact table counts from one repeatable-read, read-only snapshot. Counts can mismatch if application writes continue between manifest capture and `pg_dump`.

Load the PostgreSQL password from the deployment's secret manager. Record whether Node was already running so the procedure does not start a service that was intentionally stopped:

~~~bash
: "${OPENSHIELD_POSTGRES_PASSWORD:?Load the PostgreSQL password from your secret manager}"
export PGPASSWORD="$OPENSHIELD_POSTGRES_PASSWORD"

NODE_WAS_RUNNING=false
if docker compose ps --status running --services | grep -Fxq openshield-node; then
  NODE_WAS_RUNNING=true
fi
restart_node() {
  if [ "$NODE_WAS_RUNNING" = true ]; then
    docker compose start openshield-node
  fi
}
trap restart_node EXIT
docker compose stop openshield-node
~~~

Capture the source manifest while writers are stopped:

~~~bash
SOURCE_TEST_DATABASE_URL="host=openshield-db port=5432 dbname=openshield user=openshield"
docker compose run --rm --no-deps \
  --user "$(id -u):$(id -g)" \
  -e "OPENSHIELD_DATABASE_URL=$SOURCE_TEST_DATABASE_URL" \
  -e PGPASSWORD \
  -v "$PWD/backups:/reports" openshield-test \
  python scripts/ops/verify_database_restore.py \
  --statement-timeout-ms 120000 capture \
  --output /reports/source-manifest.json
~~~

The manifest contains database/version metadata, schema migration names/versions and exact row counts for all public base tables. It contains no event payloads, credentials, host identifiers or other row contents. The verifier creates the manifest atomically with mode 0600.

Create a fresh temporary workspace inside PostgreSQL and make the backup from the same quiesced source:

~~~bash
CONTAINER_WORK_DIR="$(docker compose exec -T openshield-db mktemp -d /tmp/openshield-restore-drill.XXXXXX)"
docker compose cp scripts/backup.sh "openshield-db:$CONTAINER_WORK_DIR/backup.sh"
docker compose exec -T -e PGPASSWORD \
  -e "OPENSHIELD_DATABASE_URL=host=127.0.0.1 port=5432 dbname=openshield user=openshield" \
  openshield-db sh "$CONTAINER_WORK_DIR/backup.sh" "$CONTAINER_WORK_DIR"

BACKUP_PATH="$(docker compose exec -T openshield-db sh -c \
  'set -- "$1"/openshield-*.dump; [ -f "$1" ] && printf "%s\\n" "$1"' \
  sh "$CONTAINER_WORK_DIR")"
BACKUP_FILE="backups/$(basename "$BACKUP_PATH")"
docker compose cp "openshield-db:$BACKUP_PATH" "$BACKUP_FILE"
~~~

Create a new, isolated restore target; never use the source database as the target:

~~~bash
RESTORE_DATABASE="openshield_restore_test"
RESTORE_DATABASE_URL="host=127.0.0.1 port=5432 dbname=$RESTORE_DATABASE user=openshield"
docker compose exec -T openshield-db createdb -U openshield "$RESTORE_DATABASE"

docker compose cp scripts/restore.sh "openshield-db:$CONTAINER_WORK_DIR/restore.sh"
docker compose exec -T \
  -e PGPASSWORD -e "OPENSHIELD_DATABASE_URL=$RESTORE_DATABASE_URL" \
  -e OPENSHIELD_RESTORE_CONFIRM=YES \
  openshield-db sh "$CONTAINER_WORK_DIR/restore.sh" "$BACKUP_PATH"
~~~

The restore script validates the archive, checks the target using `psql`, and refuses unless the target contains no user tables, views, sequences, functions, custom types, or non-default schemas. If the preflight query errors or returns an unexpected value, restore fails closed. It then invokes `pg_restore --single-transaction --exit-on-error`; PostgreSQL rolls back the restore if any archive command fails. It never drops, truncates, or cleans an existing database.

Compare the restored database with the source manifest:

~~~bash
RESTORE_TEST_DATABASE_URL="host=openshield-db port=5432 dbname=$RESTORE_DATABASE user=openshield"
docker compose run --rm --no-deps \
  --user "$(id -u):$(id -g)" \
  -e "OPENSHIELD_DATABASE_URL=$RESTORE_TEST_DATABASE_URL" \
  -e PGPASSWORD \
  -v "$PWD/backups:/reports" openshield-test \
  python scripts/ops/verify_database_restore.py \
  --statement-timeout-ms 120000 verify \
  --manifest /reports/source-manifest.json
~~~

The verifier exits non-zero when the target has the same database name as the source, a different PostgreSQL major version, different migration history, missing/extra public tables, or any row-count mismatch. It uses a repeatable-read, read-only snapshot and per-statement timeout. Counting every table reads the tables and may take time on a large database; raise the timeout only after reviewing staging load.

After a successful comparison, validate application readiness and key workflows against the restored database in an isolated deployment. Record backup size/time, restore time, verifier JSON output and the tested image/commit. Retain the isolated restore database until evidence is reviewed, then remove only that specifically named test database. Never drop the live database or delete persistent Docker volumes.

CI runs a real `pg_dump`/`pg_restore` round-trip between disposable PostgreSQL databases using these same backup/restore scripts and compares the restored database with the source manifest. This validates the scripts and verifier against a real PostgreSQL server; it does not replace a staging restore drill on the deployment's actual data volume.

The backup encryption key and database credentials are not contained in the archive. Protect them separately. Do not put real passwords in shell history; use a secret manager or protected environment injection. Remove the temporary container directory after evidence capture:

~~~bash
docker compose exec -T openshield-db rm -rf "$CONTAINER_WORK_DIR"
~~~

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
