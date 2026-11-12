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
- Initial OpenWrt adapter boundary with read-only probe.
- Versioned event envelope (`openshield.event.v1`) with validation and provenance.
- Event ingestion endpoint with in-process storage.
- Structured application logging.
- Docker Compose development environment.
- Dedicated Docker image target for tests and lint.
- GitHub Actions CI running lint and tests in Docker.
- Unit/API tests.
- Bearer API-key authentication with SHA-256 key hashes supplied through environment configuration.
- Role-based authorization for admin, operator, reader, and gateway principals.
- Versioned gateway connector handshake (`openshield.gateway.v1`) authenticated with a gateway-scoped API key.
- Gateway identity bound to the API key ID, read-only capability advertisement, and authenticated heartbeat.
- In-memory gateway presence/status with a 90-second freshness window and admin-only status inspection.
- Fail-closed behavior: protected endpoints return 503 when authentication configuration is missing or invalid.

### Deliberate P0 limitations

- Authentication currently uses static API keys; rotation, revocation workflow, identity federation, and gateway mTLS bootstrap remain future work.
- API key hashes are configured through `OPENSHIELD_API_KEYS`; raw API keys are never stored by the application.
- OpenWrt adapter is a safe stub; the outbound connector agent can run on a nearby Linux/Docker host, and an on-device OpenWrt agent plus actual OpenWrt telemetry/configuration transport are not implemented yet. The agent advertises no OpenWrt capabilities until those operations are real.
- Gateway connection state is in-memory and is lost on Node restart; heartbeat freshness is evaluated when status is queried (90-second timeout).
- Registry and events are in-memory; PostgreSQL persistence/migrations remain pending.
- Audit trail is not yet durable. Authentication decisions are not currently persisted as audit records.
- No metrics exporter, reconnect loop, or hardware validation exists.
- No firewall or forwarding configuration is changed. The connector is not inline.

## Docker-first development

Docker Engine and the Docker Compose plugin are the only local runtime/test prerequisites. Python, Ruff, and Pytest do not need to be installed on the host.

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

Stop the API without deleting persisted Docker data:

```bash
docker compose down
```

Test and lint services use the `tools` profile and run on demand. They do not start with the API. The application image excludes development dependencies; the test/lint image installs the project dependencies from `backend/pyproject.toml`. Tests use `httpx2` with Starlette TestClient, and pytest treats all warnings as errors so deprecations cannot silently accumulate. Docker image installs explicitly acknowledge root execution to keep build logs clean; GitHub Actions uses checkout v5 (Node.js 24).

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

Missing or invalid credentials return `401`; valid credentials without the required permission return `403`. Missing or malformed server-side key configuration returns `503` on protected endpoints and makes readiness return `503`. Keys shorter than 32 characters are rejected. Authentication failures do not expose key material.

## Gateway connector protocol v1

A minimal outbound connector agent is included for deployment on a nearby Linux/Docker host. It uses the Python standard library, verifies TLS certificates by default, sends a versioned handshake, and maintains presence with bounded reconnect backoff. It does not yet query OpenWrt or collect real gateway events.

Configure `OPENSHIELD_GATEWAY_ID` to match the gateway API key record's `key_id`, and set `OPENSHIELD_GATEWAY_API_KEY` to the raw key. Start the optional connector profile:

```bash
docker compose --profile gateway up --build -d openshield-node openshield-gateway-connector
```

The connector has no dependency on Node health and never sits in the packet-forwarding path. If the Node is unavailable, it retries; gateway traffic forwarding remains independent.


A gateway connects using a dedicated API key whose configured `key_id` must equal the gateway's `gateway_id`. The key must have the `gateway` role. The connector sends `openshield.gateway.v1` with its type, version, and declared capabilities (currently none, until a real OpenWrt data adapter is connected):

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

The protocol currently permits only read-only capability declarations (`discover`, `health_check`, and `read_events`); configuration writes and action execution are rejected. The bundled agent advertises no integration capabilities yet because it does not collect gateway telemetry. Administrators can inspect `GET /api/v1/gateways`; a gateway is reported as stale after 90 seconds without a heartbeat. This initial registry is in-memory. It is a protocol/API foundation, not yet an installable OpenWrt-side daemon; gateway forwarding remains independent of the Node.

## API quick start

Register an OpenWrt integration (requires `integrations:write`):

```bash
curl -X POST http://localhost:8000/api/v1/integrations \
  -H "Authorization: Bearer $OPENSHIELD_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"integration_id":"openwrt-lab","kind":"openwrt","display_name":"Lab gateway","config":{"base_url":"https://192.0.2.1"}}'
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

## P0 roadmap status

| Workstream | Status |
|---|---|
| Repository baseline and docs | In progress |
| Node API and health checks | Implemented |
| Integration registry and capability model | Implemented (in-memory) |
| Initial OpenWrt adapter boundary | Implemented (read-only stub) |
| Versioned event schema and normalizer | Implemented |
| Event ingestion | Implemented (in-memory) |
| API-key authentication | Implemented (static key hashes) |
| RBAC | Implemented (admin, operator, reader, gateway) |
| Gateway connector protocol v1, identity binding, and heartbeat | Implemented (Node API; in-memory) |
| Nearby-host connector agent with reconnecting HTTP client | Implemented (no OpenWrt telemetry yet) |
| On-device OpenWrt agent and secure bootstrap/mTLS | Pending |
| Key rotation/revocation | Pending |
| Durable persistence and audit | Pending |
| Structured logging | Implemented |
| Metrics | Pending |
| Secure connector bootstrap | Pending |
| Disconnect/recovery and real gateway validation | Pending |
| Docker-first runtime, lint, and test environment | Implemented |
| CI and automated tests | Implemented; runs in Docker |

CI uses Docker Compose for lint and tests, so local validation and CI share the same Python/container build. Ruff checks are kept clean, and pytest treats warnings as errors. A P0 item is complete only when its exit criteria in PLAN.md are verified. This README is updated with each increment and must not imply production readiness before the remaining security and reliability work is complete.

## Security

API-key authentication does not encrypt traffic; terminate HTTPS/TLS at the deployment boundary and never expose the development HTTP port to untrusted networks. Until gateway mTLS/bootstrap, durable audit, key rotation/revocation, and deployment hardening are complete, run only in a trusted development environment. Store `.env` securely and never commit gateway credentials, API keys, private keys, key hashes, or real network event data.

## License

License not selected yet.
