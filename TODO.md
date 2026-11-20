# OpenShield — Engineering TODO and audit findings

**Audit date:** 2026-11-19  
**Reviewed baseline:** `main` at `1f50562f77472934138d955517e57783584c6294`  
**Scope:** repository tree (190 entries), README/PLAN/docs, Docker Compose and Dockerfiles, GitHub Actions, API/authentication, storage/migrations, gateway connector and spool, sensors, DNS polling, threat intelligence, AI, policy execution, operations scripts, and relevant tests.

This file is the canonical engineering backlog. Only items with current evidence remain here; closed historical issues are not repeated as open work.

## Current delivery status

| Phase | Software status | Remaining acceptance boundary |
|---|---|---|
| P0 — Foundation and Gateway | Implemented; CI-validated | Real OpenWrt hardware and forwarding-independence validation (#17) |
| P1 — Network Visibility | Implemented; CI-validated | Real Suricata/Zeek deployment validation (#18) |
| P2 — Privacy Intelligence | Implemented; CI-validated | Operational capacity validation is tracked under #19 |
| P3 — Threat Intelligence | Implemented; CI-validated | Provider credentials, quotas, and deployment-specific operational review |
| P4 — Hybrid AI | Implemented; CI-validated | Validate local Ollama connectivity and cloud opt-in/privacy in the target deployment |
| P5 — Policy and bounded response | Implemented; disabled by default | Physical UCI/firewall ACL, execution, TTL rollback and fail-safe acceptance before enabling |
| P6 — Enterprise readiness baseline | Implemented | Not multi-tenant or enterprise identity-ready; RBAC and tenant isolation remain future scope |

The latest main CI run at the reviewed baseline passed, including build, Ruff, mypy, pip-audit, Python tests, dashboard browser tests, PostgreSQL backup/restore drill, and non-root startup smoke tests. This is automated software evidence, not hardware or production acceptance.

## Open GitHub acceptance issues

### P0 — OpenWrt physical acceptance

**[Issue #17 — Validate gateway behavior on physical hardware](https://github.com/squassina/OpenShield-luna/issues/17)**

- Record Dynalink DL-WRX36 model/board, OpenWrt release, kernel, rpcd and LuCI versions.
- Verify authenticated read-only access to `system.board`, `network.interface.dump`, `luci-rpc.getHostHints`, and `luci-rpc.getDHCPLeases` using a least-privilege rpcd account.
- Compare discovered MAC, hostname, IPv4/IPv6, DHCP lease and logical-interface values with known wired and wireless clients.
- Verify first/last-seen persistence, IP changes, offline transition, rediscovery, connector restart, Node outage, spool recovery and drain.
- From an independent LAN client, continuously verify LAN, DNS and Internet forwarding while the Node is stopped. Do not infer forwarding independence from CI or container health.
- Confirm the P0 discovery path does not change firewall, routing, wireless, VLAN, DNS or forwarding settings.
- **Additional P5 release gate:** before enabling enforcement, validate the separate, allowlisted UCI firewall command path on real firmware: dedicated write ACL scope, source/destination direction, rule verification, apply/confirm/revert behavior, emergency-stop behavior, TTL rollback and recovery after connector/Node restart. Keep enforcement disabled until evidence exists.

### P1 — Live sensor acceptance

**[Issue #18 — Validate real Suricata and Zeek deployments](https://github.com/squassina/OpenShield-luna/issues/18)**

- Deploy both sensors on an authorized capture host or SPAN/mirror interface; do not install them on OpenWrt.
- Record exact sensor, OS/kernel, shipper and OpenShield versions and configuration.
- Verify real EVE and Zeek JSON delivery for supported event types.
- Test checkpointed offsets, duplicate retries, malformed/oversized batches, log rotation, sensor restart, Node outage/recovery and freshness transitions.
- Measure packet drops, CPU, memory, disk, shipper backlog and sustained throughput.
- Attach sanitized evidence. Synthetic repository fixtures are not production captures and do not certify a sensor release.

### P1 — Database capacity and disaster recovery

**[Issue #19 — Sustained load, query plans and backup/restore](https://github.com/squassina/OpenShield-luna/issues/19)**

- Run the sequential synthetic benchmark at 1k/10k/50k events against staging or a representative deployment. Record hardware, CPU/memory, PostgreSQL version, image/commit, DB volume growth, throughput and p50/p95/p99 request latency.
- Review read-only query plans and index usage with representative data. Use `EXPLAIN ANALYZE` only in staging because it executes the SELECTs.
- Do not add partitioning/indexes without measured evidence of a bottleneck.
- Repository tooling now provides atomic custom-format backup publication, fail-closed restore preflight, one-transaction restore, a source-manifest verifier, and a real PostgreSQL round-trip in CI. Remaining deployment acceptance: restore a backup from the actual data volume into an isolated database; record backup size/time, restore time, manifest comparison and application-level validation.
- Keep retention disabled unless a retention policy is explicitly approved.

## Engineering debt found in the repository review

### P1 — Correctness, security and operational visibility

- [x] **Enforce the single-process Node assumption.** FastAPI startup acquires a PostgreSQL session-level advisory lock on a dedicated connection before opening the pool or applying schema migrations; a second Node fails before it can migrate or start background loops. Tests cover lock-before-open ordering, contention, release, and lifespan cleanup. One Uvicorn worker and one Node replica per database remain required; multi-instance support still needs shared rate limiting and coordinated workers. Base guard implemented in PR #144; migration-order hardening in PR #149. Evidence: `backend/openshield/api/main.py`, `backend/openshield/core/storage.py`, `backend/tests/test_storage_pool.py`.

- [x] **Bound Prometheus metric cardinality.** DNS polling uses only bounded provider/category/outcome labels and omits user-controlled `integration_id`. `MetricsRegistry` caps distinct metric/label series at 4,096 by default and reports rejected new series through `openshield_metrics_samples_dropped_total`. Tests cover cap enforcement, overflow visibility, and stable series reuse. Implemented in PR #145. Evidence: `backend/openshield/core/metrics.py`, `backend/openshield/privacy/polling.py`, `backend/tests/test_metrics_registry.py`.

- [x] **Expose gateway spool counters and alert on loss/pressure.** The connector sends its durable SQLite spool snapshot on each heartbeat; Node validates the counters and exports per-gateway pending/capacity gauges, cumulative eviction/coalescing/drop counters, and last-report timestamp. Labels use only `gateway_id` and remain subject to the 4,096-series registry cap. The runbook includes alerts for high-water marks, drops/evictions, stale telemetry, and rejected metric series. Self-reported stats are monitoring-only and never control enforcement. Implemented on `main`. Evidence: `backend/openshield/gateway/spool.py`, `backend/openshield/gateway/agent.py`, `backend/openshield/api/routers/gateway.py`, `backend/tests/test_api.py`, `backend/tests/test_gateway_client.py`, `docs/operations/gateway-spool-observability.md`.

- [x] **Make restore preflight fail closed.** `scripts/restore.sh` requires `OPENSHIELD_RESTORE_CONFIRM=YES`, verifies that the archive is readable, and uses `psql` to reject targets containing user tables/views/sequences, functions, custom types, or non-default schemas. Query failure or an unexpected result is rejected; restore runs with `pg_restore --single-transaction --exit-on-error`. Tests cover empty and non-empty targets, unknown preflight output, confirmation, and transactional failure. No automatic drop/clean behavior is used.

- [x] **Remove insecure Compose database fallback for production use.** Development mode retains the existing convenience fallback; `production` mode rejects known defaults in the PostgreSQL healthcheck and the Node startup guard requires an explicit password of at least 16 characters, rejects whitespace-wrapped/default values, validates the PostgreSQL URL, and requires URL/password equality. README documents secret-manager configuration and existing-volume password rotation. Implemented in PR #147 (CI #1208 passed). Evidence: `docker-compose.yml`, `backend/openshield/core/deployment.py`, `backend/openshield/api/main.py`, `backend/tests/test_deployment.py`.

- [x] **Decide and document spool encryption at rest.** Accepted Home boundary: the single-administrator deployment trusts the connector host; OpenShield does not encrypt the SQLite spool. Directory/database/WAL/SHM permissions and UID 10001 limit access by unrelated unprivileged host users but do not protect against host root, Docker-daemon access, host compromise or disk theft. Deployments outside that boundary must use encrypted host/volume storage and encrypted backups. The runbook documents SQLite online backup (WAL-safe), restore ownership/modes, command-result receipt risk, and validation. This closes the design/documentation decision, not the residual at-rest encryption risk. Evidence: `backend/openshield/gateway/spool.py`, `docker-compose.yml`, `docs/operations/gateway-spool-storage.md`.

- [x] **Add local tamper-evident audit chain.** Canonical SHA-256 hashes cover record ID, UTC timestamp, actor, action, target, details and predecessor. Migration v4 backfills existing rows transactionally; database triggers validate predecessor inserts, advance the chain head, and reject UPDATE/DELETE/TRUNCATE. `GET /api/v1/audit/integrity` verifies records and head in a repeatable-read snapshot. Implemented in PR #150 (CI #1219 passed). This detects isolated edits/reordering, not a privileged DBA who rewrites the complete chain and triggers. No automatic deletion is enabled. Evidence: `backend/openshield/core/audit_integrity.py`, `backend/openshield/core/storage.py`, `backend/openshield/api/routers/audit.py`, `docs/operations/audit-integrity.md`.

- [ ] **Anchor audit exports to independent immutable/WORM storage.** The local hash chain is not an external trust anchor. Export verified records and checkpoints to a destination controlled separately from Node/PostgreSQL administrators; define restore and key/identity controls.

- [ ] **Approve audit retention and archival policy.** Define retention periods, legal hold, archive cadence, authorized deletion and checkpoint continuation before implementing automatic deletion. Retention remains disabled.

### P2 — Reproducibility and maintainability

- [x] **Pin the complete build inputs.** Python 3.12 runtime, development and build dependencies are resolved into hash-pinned `requirements.txt`, `requirements-dev.txt` and `requirements-build.txt` files. The Dockerfile installs only with `--require-hashes`; pip 26.3 and setuptools 84.1.0 are pinned, and setuptools is declared as the exact build backend. Python 3.12, Playwright 1.64.1 and PostgreSQL 16 Alpine image references carry registry manifest digests. Playwright package/image versions stay aligned. Dependabot updates pip, Docker and Actions inputs weekly; the scheduled refresh workflow opens a PR for lock and digest changes. Implemented on this branch; CI required. Evidence: `backend/pyproject.toml`, `backend/requirements*.txt`, `backend/requirements-build.in`, `Dockerfile`, `docker-compose.yml`, `.github/dependabot.yml`, `.github/workflows/resolve-python-locks.yml`, `docs/operations/build-reproducibility.md`.

- [x] **Reconcile PLAN.md with the merged implementation.** Updated P3/P4/P5/P6 status text to reflect the CI-validated `main` baseline, corrected PostgreSQL migration/pooling/audit and gateway-spool details, and replaced historical hardware-issue links with the active #17 acceptance issue. Remaining physical and production acceptance boundaries stay explicit.

- [ ] **Reduce large-module maintenance cost incrementally.** Two cohesive storage slices are in review: eight policy/decision persistence methods in `backend/openshield/core/storage_policies.py`, and 13 integration/secret/poll-cursor methods in `backend/openshield/core/storage_integrations.py`. `PostgresStore` composes both mixins and retains the same public methods, SQL, transaction boundaries and audit behavior. Together they remove roughly 366 lines from `storage.py` (about 2,613 to 2,247 lines) without changing callers. Further storage slices and the single roughly 90 KB dashboard asset remain; extract only where a clear seam and regression coverage exist.

- [x] **Add documentation and dashboard static checks to CI.** CI runs `scripts/ops/check_static_assets.py` before container builds. The standard-library checker validates repository-relative Markdown links/images and runs `node --check` against inline JavaScript extracted from `backend/openshield/dashboard.html`; unit tests cover fenced/inline code, balanced parentheses, root/relative links, and inline/module scripts. Implemented in PR #151 (CI #1222 passed). Evidence: `scripts/ops/check_static_assets.py`, `backend/tests/test_static_checks.py`, `.github/workflows/ci.yml`.

- [x] **Review backup artifact handling.** `scripts/backup.sh` writes to a collision-safe temporary file in the destination directory, validates it with `pg_restore --list`, enforces mode 0600, and publishes it with an atomic rename. An EXIT trap removes incomplete files after dump, validation, or publication failures. Tests cover unique names, permissions, and cleanup.

## Operational constraints to keep visible

- Admin HTTP Basic is optional and disabled by default in the residential profile. When disabled, anyone able to reach the Node API can administer it; keep the API on loopback or a trusted LAN.
- Gateway authentication and sensor bearer credentials are separate from user identity. They do not provide per-user roles or tenant boundaries.
- Gateway spool contents are not encrypted at rest. Protect the host, volume and backups.
- Prometheus counters and rate-limit state are process-local. They reset on restart and are not distributed.
- DNS polling processes one provider page per integration per cycle; high-volume catch-up depends on the configured polling interval.
- Backup ciphertext is not sufficient to recover provider credentials without the matching Fernet key. Back up the key separately and protect it.
- Business/SaaS use remains blocked on user identity, RBAC, organization/site ownership, tenant isolation and a security review.

## Completed work — do not re-open as TODO without new evidence

- P0 database persistence, migration framework, integration registry, gateway handshake, durable outbox/retry, audit baseline, metrics endpoint, read-only OpenWrt discovery and inventory software.
- P1 Suricata/Zeek normalizers, bounded ingestion, per-sensor bearer credentials, credential rotation/revocation, rate limits and request-body limits.
- P2 dashboard, service lifecycle, encrypted integration credentials, automatic Pi-hole/AdGuard polling, durable cursors, provider-list reconciliation, CNAME tracker feed provenance and overrides.
- P3 CrowdSec/MISP enrichment, cache, deterministic risk scoring and audited incidents.
- P4 local Ollama and opt-in sanitized OpenAI investigation, schema validation and audit.
- P5 exact-match policies, approval, emergency stop, bounded DNS/OpenWrt execution, TTL and rollback logic; hardware validation remains a gate.
- P6 multi-gateway summaries, loopback-by-default publishing and PostgreSQL backup/restore tooling.
- Event keyset pagination, opt-in batched retention, sensor fixtures, benchmark/query-plan tooling, atomic backup publication, fail-closed transactional restore, and a disposable PostgreSQL backup/restore round-trip in CI.
- Playwright browser setup uses the official browser image; no apt-based browser dependency installation is needed in CI. See [dashboard browser test runbook](docs/operations/dashboard-browser-tests.md).
