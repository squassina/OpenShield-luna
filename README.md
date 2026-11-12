# OpenShield

Autonomous Network Security & Privacy Intelligence — self-hosted, gateway-first, local-first.

OpenShield integrates existing network and security tools. It normalizes signals, correlates evidence, and explains findings. It does not replace a firewall, DNS resolver, IDS, or SIEM.

## Architecture baseline

- **Gateway-first:** a lightweight connector communicates with a separate OpenShield Node. Gateway forwarding must never depend on Node availability.
- **Hybrid integrations:** authorized capability discovery where supported, with manual configuration as fallback.
- **Local-first AI:** local inference is the default. Cloud AI is optional, disabled by default, and receives minimized/sanitized context.
- **Deterministic control:** AI recommends; deterministic policy authorizes. P0 exposes no traffic-blocking action.
- **Modular monolith:** FastAPI backend with explicit modules and versioned contracts.

See [PLAN.md](PLAN.md) for the product plan, roadmap, architecture decisions, risks, and exit criteria.

## P0 — Foundation & Gateway Connectivity

### Implemented in this baseline

- FastAPI Node API with liveness/readiness endpoints.
- Integration registry with explicit capability declarations.
- Manual integration registration through the API.
- Read-only OpenWrt rpcd/ubus client with authenticated session login, bounded HTTP timeout/response size, board/interface discovery, and health check.
- Versioned event envelope (`openshield.event.v1`) with validation and provenance.
- PostgreSQL-backed integration registry, gateway presence, and event ingestion.
- Structured application logging.
- Docker Compose development environment.
- Dedicated Docker image target for tests and lint.
- GitHub Actions CI running lint and tests in Docker.
- Unit/API tests.
- Bearer API-key authentication with SHA-256 key hashes supplied through environment configuration.
- Role-based authorization for admin, operator, reader, and gateway principals.
- Versioned gateway connector handshake (`openshield.gateway.v1`) authenticated with a gateway-scoped API key.
- Gateway identity bound to the API key ID, read-only capability advertisement, and authenticated heartbeat.
- Persistent gateway presence/status with a 90-second freshness window and admin-only status inspection.
- Fail-closed behavior: protected endpoints return 503 when authentication configuration is missing or invalid.

### Deliberate P0 limitations

- Authentication currently uses static API keys; rotation, revocation workflow, identity federation, and gateway mTLS bootstrap remain future work.
- API key hashes are configured through `OPENSHIELD_API_KEYS`; raw API keys are never stored by the application.
- OpenWrt discovery and health checks run through read-only ubus calls from the nearby-host gateway connector. The connector sends normalized discovery and health events to the Node using openshield.event.v1. Credentials are supplied only to the connector through environment variables; integration config rejects secret-like fields. An on-device OpenWrt agent is not implemented.
- Gateway, integration, and event state is persisted in PostgreSQL; heartbeat freshness is evaluated when status is queried (90-second timeout).
- PostgreSQL persistence is implemented with idempotent schema creation; formal versioned migrations and backup/restore automation remain pending.
- Durable audit records cover integration registration, gateway connection, event ingestion, and gateway event-source spoof attempts. API-key authentication failures are not yet persisted; retention, tamper-evidence, and export controls remain pending.
- The protected Prometheus `/metrics` endpoint currently exposes process-local request, event, gateway, and authorization-denial counters. Counters reset on process restart; histograms, database gauges, external scraping/alerting, and real-hardware validation remain pending. The nearby-host connector forwards discovery/health data; broader OpenWrt event feeds remain pending.
- No firewall or forwarding configuration is changed. The connector is not inline.

## Docker-first development

Docker Engine and the Docker Compose plugin are the only local runtime/test prerequisites. Compose starts PostgreSQL 16 with a named persistent volume; Python, Ruff, and Pytest do not need to be installed on the host.

Create a local environment file and configure at least one API key hash before using protected API endpoints:

1. Copy `.env.example` to `.env`.
2. Generate a secret: `openssl rand -hex 32`.
3. Calculate its hash: `printf '%s' '<secret>' | sha256sum`.
4. Put the SHA-256 hash in the `key_hash` field and keep the original secret outside the repository.

Build and start the API:

```bash
docker compose up --build -d openshield-node
```

Run lint and tests in the same Python 3.12 container environment used by CI:

```bash
docker compose build openshield-test openshield-lint
docker compose run --rm openshield-lint
docker compose run --rm openshield-test
```

API: http://localhost:8000  
OpenAPI: http://localhost:8000/docs  
Liveness: http://localhost:8000/health/live  
Readiness: http://localhost:8000/health/ready

Stop the API and database without deleting persisted Docker data:

```bash
docker compose down
```

Test and lint services use the `tools` profile and run on demand. The test service starts PostgreSQL as a dependency; lint does not. The API starts PostgreSQL automatically. The application image excludes development dependencies; the test/lint image installs the project dependencies from `backend/pyproject.toml`. Tests use `httpx2` with Starlette TestClient, and pytest treats all warnings as errors so deprecations cannot silently accumulate. Docker image installs explicitly acknowledge root execution to keep build logs clean; GitHub Actions uses checkout v5 (Node.js 24).

## API authentication and roles

All `/api/v1` endpoints require an API key in the HTTP Bearer header. Health endpoints remain public for container orchestration.

Configure `OPENSHIELD_API_KEYS` as a JSON array. Each record contains a unique key ID, role, and lowercase SHA-256 hash of the secret:

```json
[
  {
    "key_id": "local-admin",
    "role": "admin",
    "key_hash": "<64-character-sha256-hex>"
  }
]
```

Example authenticated request:

```bash
curl http://localhost:8000/api/v1/integrations \
  -H "Authorization: Bearer $OPENSHIELD_API_KEY"
```

| Role | Permissions |
|---|---|
| `admin` | Read/write integrations and events |
| `operator` | Read integrations and read/ingest events |
| `reader` | Read integrations and events |
| `gateway` | Connect, send heartbeats, and ingest events for its own identity |

Missing or invalid credentials return `401`; valid credentials without the required permission return `403`. Missing or malformed server-side key configuration returns `503` on protected endpoints and makes readiness return `503`. Readiness also checks PostgreSQL connectivity. Keys shorter than 32 characters are rejected. Authentication failures do not expose key material.

## Gateway connector protocol v1

A minimal outbound connector agent is included for deployment on a nearby Linux/Docker host. It uses the Python standard library, verifies TLS certificates by default, sends a versioned handshake, maintains presence with bounded reconnect backoff, queries OpenWrt through read-only ubus RPC, and forwards normalized discovery/health events.

Configure `OPENSHIELD_GATEWAY_ID` to match the gateway API key record's `key_id`, and set `OPENSHIELD_GATEWAY_API_KEY` to the raw key. Start the optional connector profile:

```bash
docker compose --profile gateway up --build -d openshield-node openshield-gateway-connector
```

The connector has no dependency on Node health and never sits in the packet-forwarding path. If the Node is unavailable, it retries; gateway traffic forwarding remains independent.


A gateway connects using a dedicated API key whose configured `key_id` must equal the gateway's `gateway_id`. The key must have the `gateway` role. The connector sends `openshield.gateway.v1` with its type, version, and declared capabilities (discover and health_check when OpenWrt RPC settings are configured; otherwise none):

```bash
curl -X POST http://localhost:8000/api/v1/gateway/connect \\
  -H "Authorization: Bearer $OPENSHIELD_GATEWAY_API_KEY" \\
  -H 'Content-Type: application/json' \\
  -d '{"protocol_version":"openshield.gateway.v1","gateway_id":"test-gateway","gateway_type":"openwrt","connector_version":"0.1.0","capabilities":[]}'

curl -X POST http://localhost:8000/api/v1/gateway/heartbeat \\
  -H "Authorization: Bearer $OPENSHIELD_GATEWAY_API_KEY" \\
  -H 'Content-Type: application/json' \\
  -d '{"protocol_version":"openshield.gateway.v1"}'
```

The protocol currently permits only read-only capability declarations (`discover`, `health_check`, and `read_events`); configuration writes and action execution are rejected. The bundled nearby-host agent advertises `discover` and `health_check` only when configured with OpenWrt RPC credentials; it emits discovery and health events, not a full firewall/network event feed. Administrators can inspect `GET /api/v1/gateways`; a gateway is reported as stale after 90 seconds without a heartbeat. This initial registry is in-memory. The agent is not yet installable as an on-device OpenWrt daemon; gateway forwarding remains independent of the Node.

## OpenWrt read-only discovery

For physical gateway testing, outage/restart drills, and acceptance evidence, follow [the OpenWrt P0 validation runbook](docs/operations/openwrt-validation.md).

Register the integration in the Node first. Keep credentials out of integration config:

```bash
curl -X POST http://localhost:8000/api/v1/integrations \
  -H "Authorization: Bearer $OPENSHIELD_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"integration_id":"openwrt-lab","kind":"openwrt","display_name":"Lab gateway"}'
```

Set OPENSHIELD_OPENWRT_URL, OPENSHIELD_OPENWRT_USERNAME, OPENSHIELD_OPENWRT_PASSWORD, and OPENSHIELD_INTEGRATION_ID for the gateway connector service. OPENSHIELD_INTEGRATION_ID must match both OPENSHIELD_GATEWAY_ID and the integration registered in the Node. The Node rejects gateway events whose source integration ID does not match the authenticated gateway key ID. The account should have only the ubus permissions needed for session.login, system.board, and network.interface.dump. Never put passwords or tokens in integration config; the API rejects secret-like config keys.

The connector performs discovery at startup and sends a gateway.discovery event. It sends gateway.health events after each heartbeat. These events are ingested through the authenticated gateway API key and retain the registered integration ID as source provenance. The client verifies TLS certificates by default, limits RPC requests to 5 seconds and response bodies to 1 MiB, and does not expose credentials in error messages. For HTTP-only OpenWrt management, isolate the management network; HTTP does not protect credentials in transit. No firewall, routing, wireless, or forwarding settings are modified. Real hardware compatibility remains unverified until tested against a supported OpenWrt device.

## API quick start

Register an OpenWrt integration (requires `integrations:write`):

```bash
curl -X POST http://localhost:8000/api/v1/integrations \
  -H "Authorization: Bearer $OPENSHIELD_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"integration_id":"openwrt-lab","kind":"openwrt","display_name":"Lab gateway"}'
```

List integrations (requires `integrations:read`):

```bash
curl http://localhost:8000/api/v1/integrations \
  -H "Authorization: Bearer $OPENSHIELD_API_KEY"
```

Ingest a validated event (requires `events:write`):

```bash
curl -X POST http://localhost:8000/api/v1/events \
  -H "Authorization: Bearer $OPENSHIELD_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"schema_version":"openshield.event.v1","event_id":"evt-001","source":{"integration_id":"openwrt-lab","kind":"openwrt"},"event_type":"gateway.health","occurred_at":"2026-01-01T12:00:00Z","observed_at":"2026-01-01T12:00:01Z","severity":"info","payload":{"status":"reachable"}}'
```

Read the recent audit trail (requires admin role / `audit:read`):

```bash
curl "http://localhost:8000/api/v1/audit?limit=100" \
  -H "Authorization: Bearer $OPENSHIELD_API_KEY"
```

The audit trail records successful integration registrations, gateway connections, event ingestion, and gateway event-source authorization denials. It stores actor ID, action, target, timestamp, and minimized details; it never stores raw API keys or OpenWrt passwords. Invalid/missing API-key attempts, retention policies, tamper-evident chaining, and export are not implemented yet.

## Gateway event recovery

The nearby-host connector writes discovery and health envelopes to a local SQLite outbox before delivery. It retries queued events after reconnect and removes them only after the Node acknowledges them. Event ingestion is idempotent: a retry of an already stored event ID receives HTTP 202 with status `duplicate`, allowing the connector to safely acknowledge it.

- Default spool path: `/var/lib/openshield/gateway-spool.sqlite3`.
- Docker Compose persists the directory in the `openshield-gateway-spool` named volume.
- Queue capacity is bounded to 10,000 pending events; when full, new events are rejected and logged rather than deleting older pending events.
- SQLite uses WAL and full synchronous mode; the database file is chmod 0600 and its parent directory is enforced at mode 0700.
- The spool is not encrypted at rest. Protect the Docker volume and host storage.

## Metrics

The Prometheus text endpoint is available at `GET /metrics` and requires an admin API key. It exposes request counters by method/route/status plus event ingestion, gateway connection/heartbeat, and gateway source-denial counters. Labels use FastAPI route templates to avoid high-cardinality resource IDs.

Counters are process-local and reset on restart. Histograms, database-backed gauges, alerting, and metrics scraping deployment are not included yet.

## P0 roadmap status

| Workstream | Status |
|---|---|
| Repository baseline and docs | In progress |
| Node API and health checks | Implemented |
| Integration registry and capability model | Implemented (PostgreSQL-backed) |
| OpenWrt ubus adapter, board/interface discovery, health check | Implemented (connector-side read-only; mocked tests, hardware pending) |
| Versioned event schema and normalizer | Implemented |
| Event ingestion | Implemented (PostgreSQL-backed; duplicate event IDs rejected) |
| API-key authentication | Implemented (static key hashes) |
| RBAC | Implemented (admin, operator, reader, gateway) |
| Gateway connector protocol v1, identity binding, heartbeat, and durable event outbox | Implemented (PostgreSQL presence + bounded SQLite connector spool) |
| Nearby-host connector agent with reconnecting HTTP client and discovery/health event forwarding | Implemented (mocked transport; hardware pending) |
| On-device OpenWrt agent and secure bootstrap/mTLS | Pending |
| Key rotation/revocation | Pending |
| PostgreSQL persistence for integrations, events, gateway presence, and initial audit records | Implemented; audit hardening/retention pending |
| Structured logging | Implemented |
| Metrics | Implemented (admin-protected Prometheus counters; process-local) |
| OpenWrt RPC credentials via deployment environment and config secret rejection | Implemented (static env secrets; rotation pending) |
| Disconnect/recovery and real gateway validation | Pending |
| Docker-first runtime, lint, and test environment | Implemented |
| CI and automated tests | Implemented; runs in Docker |

CI uses Docker Compose for lint and tests, so local validation and CI share the same Python/container build. Ruff checks are kept clean, and pytest treats warnings as errors. A P0 item is complete only when its exit criteria in PLAN.md are verified. This README is updated with each increment and must not imply production readiness before the remaining security and reliability work is complete.

## Security

API-key authentication does not encrypt traffic; terminate HTTPS/TLS at the deployment boundary and never expose the development HTTP port to untrusted networks. Until gateway mTLS/bootstrap, durable audit, key rotation/revocation, and deployment hardening are complete, run only in a trusted development environment. Store `.env` securely and never commit gateway credentials, API keys, private keys, key hashes, or real network event data.

## License

License not selected yet.
