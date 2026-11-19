# OpenShield — Engineering TODO and audit findings

**Audit date:** 2026-11-19  
**Reviewed baseline:** `main` at `b6037fdae4a1834fabf933f4409a3e9fa8189f8b`  
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

The latest main CI run at the reviewed baseline passed, including build, Ruff, mypy, pip-audit, Python tests, dashboard browser tests, PostgreSQL backup/restore drill, and non-root startup smoke tests. The implementation branch adds regression coverage for the fixes below; its full CI result is the acceptance gate for this batch. This remains automated software evidence, not hardware or production acceptance.

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
- Restore a backup from the actual deployment data volume into an isolated database; record backup size/time, restore time, manifest comparison and application-level validation.
- Keep retention disabled unless a retention policy is explicitly approved.

## Engineering debt found in the repository review

### P1 — Correctness, security and operational visibility

- [x] **Coordinate background workers across Node replicas.** FastAPI lifespan now acquires a PostgreSQL session-level advisory lock before starting DNS polling and response-expiration workers. The lock is held by a dedicated connection, monitored, released on shutdown/loss, and reacquired after failure. Test coverage verifies mutual exclusion and release. Rate-limit windows and failed-admin-login counters remain process-local; do not treat them as distributed protection when running multiple API workers/replicas.

- [x] **Bound Prometheus metric cardinality.** `MetricsRegistry` now enforces a global series ceiling, validates metric/label syntax and length, limits labels per series, rejects metric-type conflicts, and exports a dropped-series counter. DNS polling no longer labels series with the user-controlled `integration_id`; gateway spool telemetry uses the bounded gateway label.

- [x] **Expose gateway spool counters and pressure.** The Connector now sends pending depth, capacity, evictions, health-snapshot coalescing, and dropped-event totals in its authenticated heartbeat. The Node exports bounded Prometheus gauges/counters by gateway. Alert-rule provisioning and a Prometheus deployment remain operator-owned.

- [x] **Make restore preflight fail closed.** `scripts/restore.sh` still requires `OPENSHIELD_RESTORE_CONFIRM=YES` and now checks PostgreSQL catalogs for user relations, routines, custom types, large objects, and extra schemas before invoking `pg_restore`. It refuses non-empty targets and never drops existing objects. Script tests cover empty/non-empty targets and missing confirmation.

- [x] **Guard production deployments against development credentials.** The `production` deployment profile fails during Node import/startup unless admin Basic auth is enabled with a sufficiently long password, the PostgreSQL password is unique/long and matches the database URL, and the published bind address is a specific IP. The `home` profile retains current residential defaults; the Compose development fallback is therefore still present only for that profile.

- [x] **Encrypt the gateway spool at rest.** Event and command-result payloads are now Fernet-encrypted using the shared runtime key. Startup migrates legacy plaintext rows and re-encrypts rows using a previous key; the migration vacuums the SQLite database after checkpointing to reclaim old plaintext pages. Connector startup fails closed when the active key is missing or cannot decrypt the spool. The key and spool volume must be backed up together.

- [ ] **Complete audit lifecycle hardening.** Audit records are durable, but retention, tamper-evident chaining/signatures and external immutable export are not implemented. Define retention and export requirements before using the audit log as a compliance evidence source.

### P2 — Reproducibility and maintainability

- [ ] **Pin the complete build inputs.** Python dependencies use version ranges and base images are tag-pinned rather than digest-pinned. Add a reproducible dependency lock and pin runtime/build images by digest or a controlled update process. Keep Playwright client and browser image versions aligned.

- [ ] **Reconcile PLAN.md with the merged implementation.** Some appended P3/P4/P5/P6 status text still says implementation is on a chained feature branch or underway, while the corresponding software is present on main. P1 checkpoint and earlier P0 notes also repeat older boundaries. Keep PLAN.md as product architecture/strategy, but update implementation checkpoints to match README and this TODO.

- [ ] **Reduce large-module maintenance cost incrementally.** `backend/openshield/core/storage.py` is a 2,200+ line persistence module and `backend/openshield/dashboard.html` is a single roughly 90 KB UI asset. Extract only when there is a clear seam and regression coverage; preserve current contracts and avoid a broad rewrite.

- [ ] **Add documentation and dashboard static checks to CI.** Validate relative Markdown links and run a JavaScript syntax/lint check on the inline dashboard script. Browser tests already exercise the dashboard, but syntax checks and link validation would catch documentation drift earlier.

- [x] **Publish backups atomically.** `scripts/backup.sh` now dumps to a restrictive temporary file, verifies the archive, and atomically publishes a collision-safe final filename. Partial artifacts are cleaned on failure.

## Operational constraints to keep visible

- Admin HTTP Basic is optional and disabled by default in the residential profile. When disabled, anyone able to reach the Node API can administer it; keep the API on loopback or a trusted LAN.
- Gateway authentication and sensor bearer credentials are separate from user identity. They do not provide per-user roles or tenant boundaries.
- Gateway spool event/command-result payloads are encrypted at rest, but SQLite metadata (event IDs, timestamps and counters) remains visible. Protect the runtime-secrets and spool volumes; restore them together.
- Prometheus metrics and API rate-limit/admin-login failure windows are process-local and reset on restart. The worker lease is distributed through PostgreSQL; request throttling is not. Before horizontally scaling API workers, move rate-limit state to shared storage or an edge gateway.
- DNS polling processes one provider page per integration per cycle; high-volume catch-up depends on the configured polling interval.
- Database ciphertext and encrypted spool payloads are not sufficient to recover credentials/events without the matching Fernet key. Back up `OPENSHIELD_SECRET_KEY`, any previous key still needed for rotation, the runtime-secrets volume, and gateway spool volume together.
- Business/SaaS use remains blocked on user identity, RBAC, organization/site ownership, tenant isolation and a security review.

## Completed work — do not re-open as TODO without new evidence

- P0 database persistence, migration framework, integration registry, gateway handshake, durable outbox/retry, audit baseline, metrics endpoint, read-only OpenWrt discovery and inventory software.
- P1 Suricata/Zeek normalizers, bounded ingestion, per-sensor bearer credentials, credential rotation/revocation, rate limits and request-body limits.
- P2 dashboard, service lifecycle, encrypted integration credentials, automatic Pi-hole/AdGuard polling, durable cursors, provider-list reconciliation, CNAME tracker feed provenance and overrides.
- P3 CrowdSec/MISP enrichment, cache, deterministic risk scoring and audited incidents.
- P4 local Ollama and opt-in sanitized OpenAI investigation, schema validation and audit.
- P5 exact-match policies, approval, emergency stop, bounded DNS/OpenWrt execution, TTL and rollback logic; hardware validation remains a gate.
- P6 multi-gateway summaries, loopback-by-default publishing, production-profile credential preflight, safe PostgreSQL backup/restore scripts and encrypted gateway spool telemetry.
- Event keyset pagination, opt-in batched retention, sensor fixtures, benchmark/query-plan tooling and a disposable PostgreSQL restore round-trip in CI.
- Playwright browser setup using the official browser image; no apt-based browser dependency installation is needed in CI.
- PostgreSQL advisory-lock leadership for background workers, bounded Prometheus series, spool telemetry, production deployment preflight, restore emptiness checks, atomic backup publication, and encrypted gateway spool migration/rotation.
