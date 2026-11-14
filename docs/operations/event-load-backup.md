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

~~~bash
docker compose exec -T openshield-db psql -U openshield -d openshield -c "SELECT version();"
docker compose exec -T openshield-db psql -U openshield -d openshield -c "SELECT relname, n_live_tup, pg_total_relation_size(relid) AS bytes FROM pg_stat_user_tables ORDER BY pg_total_relation_size(relid) DESC;"
~~~

Capture EXPLAIN (ANALYZE, BUFFERS) for representative event-list queries using integration, event-type, severity and received-at filters. Run on staging because ANALYZE executes the query. Record duration, rows scanned/returned, buffers and chosen indexes.

Do not add partitioning or indexes by intuition. Change schema only when measurements show a repeatable bottleneck; include representative data and regression tests.

## 4. PostgreSQL backup

Create a custom-format backup without stopping Node:

~~~bash
mkdir -p backups
docker compose exec -T openshield-db pg_dump -U openshield -d openshield -Fc > backups/openshield-$(date -u +%Y%m%dT%H%M%SZ).dump
pg_restore --list backups/openshield-<timestamp>.dump
~~~

Store backups outside the Docker volume and encrypt at rest. Dumps contain network metadata, host identifiers, integration configuration and audit history. Treat as sensitive household/business data.

## 5. Restore drill into a separate database

Never overwrite the live database during acceptance. Create an isolated restore target:

~~~bash
docker compose exec -T openshield-db createdb -U openshield openshield_restore_test
~~~

Run pg_restore from a host with PostgreSQL client tools and network access to the database, or from a suitable client container on the Compose network:

~~~bash
pg_restore --exit-on-error --no-owner --dbname='<restore-test-dsn>' backups/openshield-<timestamp>.dump
~~~

Do not put the real password in shell history; use a protected .pgpass or equivalent secret mechanism.

Compare restored table counts, latest event timestamps, integrations, gateway/device records and audit records with the source snapshot. Start a separate Node pointed at the restore DB only in an isolated deployment with no port/config collisions. Record restore duration and warnings.

After evidence capture, remove only the isolated test database using an explicitly reviewed command. Never drop the live openshield database or delete persistent Docker volumes.

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
