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

- [ ] **Define and enforce the single-process assumption, or coordinate background workers.** DNS polling and the execution-expiration loop are started from FastAPI lifespan. Each Uvicorn worker/replica would start its own loops. Rate-limit windows and failed-admin-login counters are also in process memory. Until a PostgreSQL lease/advisory lock or dedicated worker exists, document and enforce one active scheduler instance; otherwise replicas can poll providers or process expiry concurrently and each process gets its own rate-limit budget. Evidence: `backend/openshield/api/main.py`, `backend/openshield/privacy/polling.py`, `backend/openshield/core/rate_limits.py`.

- [ ] **Bound Prometheus metric cardinality.** `MetricsRegistry` stores every distinct label tuple indefinitely and has no maximum-series guard. DNS polling adds the user-configurable `integration_id` label, so adding/removing many integrations can grow process memory and leave stale series. Prefer bounded/static labels (provider and outcome), cap series, and test churn/deletion. Evidence: `backend/openshield/core/metrics.py`, `backend/openshield/privacy/polling.py`.

- [ ] **Expose gateway spool counters and alert on loss/pressure.** SQLite already maintains `pending_events`, `capacity`, `evicted_events`, `coalesced_health_events`, and `dropped_events`. Protected events include gateway health, command results, security/audit events and high/critical severity; duplicate health snapshots may be coalesced while state transitions remain durable. However, `GatewayEventSpool.stats()` is not wired to Node metrics or an operational API. Expose bounded counters/gauges and alert on drops, evictions and sustained high-water marks. Evidence: `backend/openshield/gateway/spool.py`, `backend/openshield/gateway/agent.py`.

- [x] **Make restore preflight fail closed.** `scripts/restore.sh` requires `OPENSHIELD_RESTORE_CONFIRM=YES`, verifies that the archive is readable, and uses `psql` to reject targets containing user tables/views/sequences, functions, custom types, or non-default schemas. Query failure or an unexpected result is rejected; restore runs with `pg_restore --single-transaction --exit-on-error`. Tests cover empty and non-empty targets, unknown preflight output, confirmation, and transactional failure. No automatic drop/clean behavior is used.

- [ ] **Remove insecure Compose database fallback for production use.** `docker-compose.yml` falls back to the public development password `openshield-dev-password` when the variable is absent. Keep a convenient local-development path, but add an explicit production/preflight guard that rejects known defaults and documents mandatory unique credentials. Evidence: `docker-compose.yml`, `.env.example`, README deployment instructions.

- [ ] **Decide and document spool encryption at rest.** The gateway SQLite outbox uses restrictive file permissions, WAL and FULL synchronous writes, but it is not encrypted. For deployments where the host/volume is not trusted, use encrypted host storage or an encrypted spool design; document the accepted Home threat model and backup requirements.

- [ ] **Complete audit lifecycle hardening.** Audit records are durable, but retention, tamper-evident chaining/signatures and external immutable export are not implemented. Define retention and export requirements before using the audit log as a compliance evidence source.

### P2 — Reproducibility and maintainability

- [ ] **Pin the complete build inputs.** Python dependencies use version ranges and base images are tag-pinned rather than digest-pinned. Add a reproducible dependency lock and pin runtime/build images by digest or a controlled update process. Keep Playwright client and browser image versions aligned.

- [ ] **Reconcile PLAN.md with the merged implementation.** Some appended P3/P4/P5/P6 status text still says implementation is on a chained feature branch or underway, while the corresponding software is present on main. P1 checkpoint and earlier P0 notes also repeat older boundaries. Keep PLAN.md as product architecture/strategy, but update implementation checkpoints to match README and this TODO.

- [ ] **Reduce large-module maintenance cost incrementally.** `backend/openshield/core/storage.py` is a 2,200+ line persistence module and `backend/openshield/dashboard.html` is a single roughly 90 KB UI asset. Extract only when there is a clear seam and regression coverage; preserve current contracts and avoid a broad rewrite.

- [ ] **Add documentation and dashboard static checks to CI.** Validate relative Markdown links and run a JavaScript syntax/lint check on the inline dashboard script. Browser tests already exercise the dashboard, but syntax checks and link validation would catch documentation drift earlier.

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
- Playwright browser setup using the official browser image; no apt-based browser dependency installation is needed in CI.
