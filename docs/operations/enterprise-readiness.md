# P6 — Enterprise Readiness Baseline

This increment improves operational readiness for self-hosted Home and small Business deployments. It does not claim SaaS or multi-tenant readiness.

## Multiple gateways and sites

The Node already maintains independent gateway identities and persistent presence by `gateway_id`. Register each connector with a unique ID and use `GET /api/v1/gateways` to inspect all connected/stale gateways. The operations report includes the bounded gateway inventory and per-status totals:

```bash
curl http://localhost:8000/api/v1/reports/operations
```

The report also includes bounded summaries of integrations, incidents, policy decisions, executions, and recent audit records. `sample_limit` is explicit: counts for incidents, decisions, executions, and audit are based on the returned bounded window, not an unbounded lifetime aggregate. Do not use these sampled values for billing or compliance accounting.

## Bind the Node API safely

Compose now publishes the API on loopback by default:

```dotenv
OPENSHIELD_PUBLISH_ADDRESS=127.0.0.1
```

For trusted-LAN access, set this to the Node host's specific LAN address (not `0.0.0.0` unless you deliberately want all host interfaces):

```dotenv
OPENSHIELD_PUBLISH_ADDRESS=192.168.1.10
```

Keep firewall rules restricted to trusted clients. Do not expose port 8000 to the public Internet. Enable API Basic authentication for shared environments and configure a strong, unique password. Gateway authentication remains separate.

## Single Node process per database

The Node API acquires a PostgreSQL session-level advisory lock during FastAPI startup and holds it for the full application lifespan. The lock uses a dedicated PostgreSQL connection outside the application pool. If another Node process already owns the lock, startup fails with an explicit error rather than starting duplicate DNS polling and execution-expiration loops.

This is a deliberate single-instance constraint:

- Run one Uvicorn worker and one Node replica per database.
- Do not horizontally scale the Node service or start a second deployment against the same database.
- The lock is released during graceful shutdown and automatically when PostgreSQL closes the lock session.

Rate-limit and failed-admin-login counters remain in process memory and reset on restart. Prometheus metrics are also process-local. Multi-instance operation requires a shared rate-limit backend and a separately coordinated worker/lease design; the advisory lock is not a distributed-worker implementation.

## PostgreSQL backup

Install PostgreSQL client utilities on the host. The backup contains network events, DNS metadata, incidents, policies, credentials ciphertext, and audit records; protect it as sensitive data.

```bash
export OPENSHIELD_DATABASE_URL='postgresql://...'
sh scripts/backup.sh ./backups
```

The script uses a restrictive umask, creates a custom-format dump, verifies its archive catalog with `pg_restore --list`, and sets mode 0600. Copy verified backups to encrypted off-host storage and test restores regularly. Back up `OPENSHIELD_SECRET_KEY` separately in a secure secret manager: without the matching key, encrypted integration credentials cannot be recovered. Also retain any previous key still needed to decrypt older ciphertext.

## Restore

Restore into a newly created, empty PostgreSQL database compatible with the deployed OpenShield version. The script deliberately does not drop existing objects. It requires an explicit confirmation variable:

```bash
export OPENSHIELD_DATABASE_URL='postgresql://.../openshield_restore'
OPENSHIELD_RESTORE_CONFIRM=YES sh scripts/restore.sh ./backups/openshield-YYYYMMDDTHHMMSSZ.dump
```

Validate application readiness, integration inventory, gateway presence, recent events, incidents, policies, and audit records before switching the deployment to the restored database. Coordinate restore with the Node stopped to avoid writes during cutover.

## Deployment profiles and current boundaries

- **Home:** single-owner residential operation; optional admin Basic authentication remains disabled by default for backward compatibility. Restrict network reachability.
- **Business baseline:** multiple gateway IDs, shared operational report, API Basic authentication, explicit host binding, protected backups, and audit visibility are available.
- **Not implemented:** user accounts, RBAC, organization/site ownership, tenant isolation, centralized multi-Node control plane, per-tenant quotas, and compliance-grade immutable audit export. Do not expose one Node to mutually untrusted organizations. These require a separate identity/authorization and data-isolation design before production Business/SaaS use.
- Multiple gateway IDs provide inventory and independent connector presence, but do not create site-level authorization boundaries.
- OpenWrt physical validation and backup/restore drills against the target installation remain operational acceptance tasks.

## Validation

CI covers the operations report, multiple gateway registration, API bounds, and application build/lint. CI does not prove off-host backup durability, disaster recovery objectives, physical gateway behavior, or production security posture.
