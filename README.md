# OpenShield

Autonomous Network Security & Privacy Intelligence — self-hosted, gateway-first, local-first.

OpenShield integrates existing network and security tools. It normalizes signals, correlates evidence, and explains findings. It does not replace a firewall, DNS resolver, IDS, or SIEM.

## Product evolution

OpenShield will evolve in three deployment stages:

1. **Home (current):** no OpenShield user account, API key, or manual gateway registration. Node and connector communicate inside the trusted home network. First connector handshake automatically creates the gateway integration.
2. **Business (future):** user and organization identities, gateway enrollment, roles, credential rotation, and stronger audit controls.
3. **SaaS (future):** tenant isolation, organization administration, quotas, billing, and managed control plane.

Authentication and authorization are intentionally disabled in the current residential stage. **Do not expose the Node API to the public Internet.** Keep port 8000 on a trusted LAN and do not configure Internet port forwarding to it. OpenWrt's own RPC login remains enabled because it protects access to the router; this is separate from OpenShield API authentication.

## Architecture baseline

- **Gateway-first:** a lightweight connector communicates with a separate OpenShield Node. Gateway forwarding never depends on Node availability.
- **Hybrid integrations:** authorized capability discovery where supported, with manual configuration as fallback.
- **Local-first AI:** local inference is the default. Cloud AI is optional, disabled by default, and receives minimized/sanitized context.
- **Deterministic control:** AI recommends; deterministic policy authorizes. P0 exposes no traffic-blocking action.
- **Modular monolith:** FastAPI backend with explicit modules and versioned contracts.

See [PLAN.md](PLAN.md) for the product plan, roadmap, architecture decisions, risks, and exit criteria.

## P0 — Foundation & Gateway Connectivity

### Implemented

- FastAPI Node API with liveness/readiness endpoints.
- PostgreSQL-backed integration registry, gateway presence, events, and audit.
- Automatic registration of the gateway integration on first connector handshake.
- Read-only OpenWrt rpcd/ubus client with authenticated session login, bounded HTTP timeout/response size, board/interface discovery, and health check.
- Versioned gateway connector contract (`openshield.gateway.v1`).
- Versioned event envelope (`openshield.event.v1`) with validation and provenance.
- Nearby-host Gateway Connector with bounded reconnect behavior.
- Durable SQLite event outbox (10,000-event limit) with persistent Docker volume.
- Automated recovery tests verify offline event collection, spool persistence across recreation, retry-until-acknowledged, and queue drain after Node recovery.
- Idempotent event ingestion; retries do not duplicate stored events or audit entries.
- Durable audit records for integration registration, gateway connection, and event ingestion.
- Prometheus `/metrics` endpoint.
- Docker Compose development environment and GitHub Actions CI.
- No firewall, routing, wireless, or forwarding changes.

### Current residential API behavior

All Node API endpoints are currently unauthenticated. No API key needs to be generated, registered, stored, or passed to the connector.

The connector defaults to gateway ID `home-gateway`. On its first `POST /api/v1/gateway/connect`, the Node creates an OpenWrt integration with the same ID. Heartbeats include the gateway ID. Discovery and health events use that ID as their source.

Manual integrations can also be registered without authentication:

```bash
curl -X POST http://localhost:8000/api/v1/integrations \
  -H 'Content-Type: application/json' \
  -d '{"integration_id":"openwrt-lab","kind":"openwrt","display_name":"Lab gateway"}'
```

### Deliberate limitations

- The API has no authentication, authorization, or tenant isolation in residential mode. Anyone who can reach the API can read or modify its data.
- Restrict Node access to a trusted LAN. Do not publish port 8000 to the Internet.
- OpenWrt credentials are still required when the connector is configured to query the router. They are supplied only to the connector through environment variables and never stored in integration configuration.
- OpenWrt RPC is read-only in this baseline. The connector does not modify firewall, routing, wireless, or forwarding settings.
- PostgreSQL schema creation is idempotent; formal versioned migrations, backup/restore automation, pooling, and production database hardening remain pending.
- Audit retention, tamper-evidence, and external immutable export remain pending.
- Metrics are process-local and reset on restart.
- The connector is a nearby-host Linux/Docker agent, not an on-device OpenWrt daemon.
- Physical OpenWrt hardware/firmware compatibility and forwarding-independence validation are deferred technical debt: [Issue #2](https://github.com/squassina/OpenShield/issues/2).

## Docker-first development

Docker Engine and the Docker Compose plugin are the only local runtime/test prerequisites. Compose starts PostgreSQL 16 with a named persistent volume; Python, Ruff, and Pytest do not need to be installed on the host.

1. Copy `.env.example` to `.env`.
2. Set a local PostgreSQL password and keep `OPENSHIELD_DATABASE_URL` in sync.
3. Build and start the API:

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

Stop services without deleting persisted Docker data:

```bash
docker compose down
```

Do not use `docker compose down -v` for routine shutdown; it deletes the database and connector spool volumes.

## Gateway connector

The connector runs on a nearby Linux/Docker host. Configure the Node URL and, optionally, OpenWrt RPC access:

- `OPENSHIELD_NODE_URL` (default `http://openshield-node:8000`)
- `OPENSHIELD_GATEWAY_ID` (default `home-gateway`)
- `OPENSHIELD_GATEWAY_HEARTBEAT_INTERVAL` (default 30 seconds)
- `OPENSHIELD_OPENWRT_URL`
- `OPENSHIELD_OPENWRT_USERNAME`
- `OPENSHIELD_OPENWRT_PASSWORD`
- `OPENSHIELD_GATEWAY_SPOOL_PATH` (default `/var/lib/openshield/gateway-spool.sqlite3`)

OpenWrt URL, username, and password must be configured together. If configured, the connector advertises `discover` and `health_check`, performs discovery at startup, and sends health events after heartbeats. If omitted, the connector still registers its gateway presence but does not query OpenWrt.

Start the optional connector profile:

```bash
docker compose --profile gateway up --build -d openshield-node openshield-gateway-connector
docker compose logs -f openshield-gateway-connector
```

The connector is outbound-only and does not sit in the packet-forwarding path. When the Node is unavailable, it continues local collection and queues events in SQLite. Events are removed from the spool only after the Node acknowledges them. The queue is bounded at 10,000 events; when full, new events are rejected rather than deleting older pending events. SQLite uses WAL and FULL synchronous mode; the database file is mode 0600 and its directory mode 0700. The spool is not encrypted at rest, so protect the host and Docker volume.

## OpenWrt read-only discovery

For physical gateway testing, outage/restart drills, and acceptance evidence, follow [the OpenWrt P0 validation runbook](docs/operations/openwrt-validation.md).

The OpenWrt account should have only the ubus permissions needed for `session.login`, `system.board`, and `network.interface.dump`. Use HTTPS where supported. For HTTP-only management, isolate the management network because credentials are not encrypted in transit.

No firewall, routing, wireless, or forwarding settings are modified. Real hardware compatibility remains unverified until tested against a supported OpenWrt device.

## API quick reference

The API is unauthenticated in residential mode. Examples:

```bash
curl http://localhost:8000/api/v1/integrations
curl http://localhost:8000/api/v1/gateways
curl http://localhost:8000/api/v1/events
curl "http://localhost:8000/api/v1/audit?limit=100"
curl http://localhost:8000/metrics
```

Event ingestion requires a registered integration ID and matching source kind. Duplicate event IDs return HTTP 202 with `status=duplicate`.

## P0 roadmap status

| Workstream | Status |
|---|---|
| Repository baseline and docs | Implemented |
| Node API and health checks | Implemented |
| Integration registry and capability model | Implemented (PostgreSQL-backed) |
| Automatic home gateway registration | Implemented |
| OpenWrt ubus adapter, board/interface discovery, health check | Implemented (connector-side read-only; physical validation tracked as technical debt #2) |
| Versioned event schema and normalizer | Implemented |
| Event ingestion | Implemented (PostgreSQL-backed; idempotent retries) |
| Residential API authentication | Disabled by product decision |
| Gateway connector protocol v1, heartbeat, durable event outbox | Implemented; automated retry/recovery tests pass |
| PostgreSQL persistence and initial audit records | Implemented; audit hardening/retention pending |
| Structured logging and Prometheus metrics | Implemented (process-local counters) |
| On-device OpenWrt agent and secure bootstrap | Pending |
| Business authentication, roles, and gateway enrollment | Future phase |
| SaaS multi-tenancy and billing | Future phase |
| Docker-first runtime, lint, tests, and CI | Implemented |

P0 software scope is complete and CI-validated. Physical OpenWrt compatibility and forwarding-independence validation are deferred to [technical debt issue #2](https://github.com/squassina/OpenShield/issues/2); this does not block the P0 software closeout.

## P1 — Network Visibility

P1 adds the first network-observation pipeline. Suricata and Zeek remain external sensors; OpenShield receives their JSON events through the Node API and does not install, configure, or place either sensor inline.

### Supported visibility sources

- **Suricata EVE JSON:** alert, flow, DNS, HTTP, TLS, SSH, and anomaly records.
- **Zeek JSON logs:** conn, DNS, HTTP, and SSL records.
- Batches are limited to 500 records. Only documented fields are retained; arbitrary sensor fields and secret-like fields are discarded.
- Event IDs are deterministic for retry-safe ingestion. Event type and timestamp are part of the identity to avoid collisions across record types.
- Suricata alert severity is mapped to the common OpenShield severity model.

Register each sensor (no credentials are stored in integration config):

```bash
curl -X POST http://localhost:8000/api/v1/integrations \
  -H 'Content-Type: application/json' \
  -d '{"integration_id":"suricata-home","kind":"suricata","display_name":"Suricata"}'

curl -X POST http://localhost:8000/api/v1/integrations \
  -H 'Content-Type: application/json' \
  -d '{"integration_id":"zeek-home","kind":"zeek","display_name":"Zeek"}'
```

Send EVE records or Zeek JSON records as a JSON array:

```bash
curl -X POST http://localhost:8000/api/v1/sensors/suricata-home/events \
  -H 'Content-Type: application/json' \
  --data-binary @eve-batch.json

curl -X POST http://localhost:8000/api/v1/sensors/zeek-home/events \
  -H 'Content-Type: application/json' \
  --data-binary @zeek-batch.json
```

### Network visibility API

- `GET /api/v1/inventory/devices`: observed IP addresses, protocols, first/last seen, observation counts.
- `GET /api/v1/inventory/topology`: observed source-to-destination edges and protocol counts. This is inferred from sensor connection events, not an authoritative physical topology.
- `GET /api/v1/sensors`: sensor health based on event recency (healthy within five minutes, stale afterward, or no_data).
- `GET /api/v1/events?integration_id=...&event_type=...&severity=...&limit=...`: filtered event exploration.

The residential Node API is unauthenticated. Keep sensor ingestion endpoints and port 8000 restricted to the trusted LAN; do not expose them to the Internet. Configure Suricata/Zeek to send only the records needed for visibility. The P1 APIs do not block traffic or change gateway configuration.

The full interactive web dashboard remains in P2, consistent with the product roadmap decision.

## Security

Residential mode trusts the local network and does not authenticate API callers. Keep the Node API on a trusted LAN, restrict access at the network boundary, and never expose port 8000 directly to the Internet. OpenWrt RPC credentials remain separate and must be protected. Store `.env` securely and never commit router credentials or real network event data.

Authentication, authorization, gateway enrollment, and tenant isolation will be introduced before business or SaaS deployment.

## License

License not selected yet.
