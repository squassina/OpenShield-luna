# OpenShield

Autonomous Network Security & Privacy Intelligence — self-hosted, gateway-first, local-first.

OpenShield integrates existing network and security tools. It normalizes signals, correlates evidence, and explains findings. It does not replace a firewall, DNS resolver, IDS, or SIEM.

## Product evolution

OpenShield will evolve in three deployment stages:

1. **Home (current):** no OpenShield user account or manual gateway registration. Admin Basic authentication is optional and disabled by default. A separate gateway bearer token protects UI-managed router-secret delivery when enabled. First connector handshake automatically creates the gateway integration.
2. **Business (future):** user and organization identities, gateway enrollment, roles, credential rotation, and stronger audit controls.
3. **SaaS (future):** tenant isolation, organization administration, quotas, billing, and managed control plane.

Residential admin authentication remains disabled by default to preserve the home-user model. It can be enabled with HTTP Basic credentials; gateway-to-Node secret delivery uses a separate bearer token. **Do not expose the Node API to the public Internet.** Keep port 8000 on a trusted LAN and do not configure Internet port forwarding to it. OpenWrt's own RPC login remains enabled because it protects access to the router; this is separate from OpenShield API authentication.

## Architecture baseline

- **Gateway-first:** a lightweight connector communicates with a separate OpenShield Node. Gateway forwarding never depends on Node availability.
- **Hybrid integrations:** authorized capability discovery where supported, with manual configuration as fallback.
- **Local-first AI:** local inference is the default. Cloud AI is optional, disabled by default, and receives minimized/sanitized context.
- **Deterministic control:** AI recommends; deterministic policy authorizes. P0 remains read-only; P5 adds allowlisted DNS and OpenWrt IPv4 actions behind explicit policy and approval.
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

The default residential profile keeps admin API authentication disabled. Optional HTTP Basic authentication protects the dashboard and administrative API when `OPENSHIELD_API_AUTH_ENABLED=true`. UI-managed router credentials require a separate `OPENSHIELD_GATEWAY_TOKEN` shared by Node and connector; it is not an admin API key.

The connector defaults to gateway ID `home-gateway`. On its first `POST /api/v1/gateway/connect`, the Node creates an OpenWrt integration with the same ID. Heartbeats include the gateway ID. Discovery and health events use that ID as their source.

Manual integrations can also be registered without authentication:

```bash
curl -X POST http://localhost:8000/api/v1/integrations \
  -H 'Content-Type: application/json' \
  -d '{"integration_id":"openwrt-lab","kind":"openwrt","display_name":"Lab gateway"}'
```

### Deliberate limitations

- Admin Basic authentication is opt-in in residential mode; when disabled, anyone who can reach the API can read or modify its data. There are no user accounts, role separation, or tenant isolation.
- Restrict Node access to a trusted LAN. Do not publish port 8000 to the Internet.
- OpenWrt credentials are entered through the dashboard and encrypted at rest with `OPENSHIELD_SECRET_KEY`. They are never returned by integration APIs or stored in integration JSON. The authenticated connector receives them on connect/heartbeat. Back up the encryption key securely.
- OpenWrt discovery remains read-only. Optional P5 firewall enforcement uses a dedicated rpcd plugin and a single nftables set; it does not grant arbitrary command execution or general UCI writes.
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
- `OPENSHIELD_GATEWAY_TOKEN` (same random token on Node and connector when using UI-managed router credentials)
- `OPENSHIELD_GATEWAY_SPOOL_PATH`
- `OPENSHIELD_OPENWRT_URL`, `OPENSHIELD_OPENWRT_USERNAME`, `OPENSHIELD_OPENWRT_PASSWORD` (legacy environment-based fallback; prefer dashboard setup) (default `/var/lib/openshield/gateway-spool.sqlite3`)

For dashboard-managed credentials, set `OPENSHIELD_SECRET_KEY` on Node and the same `OPENSHIELD_GATEWAY_TOKEN` on Node and connector. Enter the router URL, RPC username, and password in the dashboard; the connector receives the encrypted-at-rest configuration after authentication. The legacy OpenWrt environment variables remain supported but are not required for ordinary setup. Use HTTPS for Node/connector traffic outside a trusted isolated network.

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

The API is unauthenticated by default in residential mode. If Basic authentication is enabled, use the browser's HTTP Basic prompt or pass `-u user:password` to curl. Gateway connect/heartbeat/event routes use the separate connector bearer token when configured. Examples:

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
| Residential admin authentication | Disabled by default; optional HTTP Basic, CSRF origin checks and failed-login rate limiting |
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
- Batches are limited to 500 records and 5 MiB by declared HTTP Content-Length. Only documented fields are retained; arbitrary sensor fields and secret-like fields are discarded.
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

- `GET /api/v1/inventory/devices`: observed, validated IP addresses, IP version/scope, protocols, first/last seen, and observation counts. Invalid, unspecified, and multicast addresses are excluded.
- `GET /api/v1/inventory/topology`: observed source-to-destination edges, protocol counts, and inferred direction (`internal`, `outbound`, `inbound`, `external`, or `other`). This is not an authoritative physical topology.
- `GET /api/v1/sensors`: sensor ingestion freshness based on the Node-generated `observed_at` timestamp (healthy within five minutes, stale afterward, or no_data). This confirms recent delivery to OpenShield, not sensor process or packet-capture health.
- `GET /api/v1/events?integration_id=...&event_type=...&severity=...&limit=...`: filtered event exploration. Filters, ordering, and limits execute in PostgreSQL.

The residential Node API is unauthenticated. Keep sensor ingestion endpoints and port 8000 restricted to the trusted LAN; do not expose them to the Internet. Configure Suricata/Zeek to send only the records needed for visibility. The P1 APIs do not block traffic or change gateway configuration.

Inventory and topology use database-side aggregation; the API does not load the full raw event history to calculate these views. Event retention, cursor pagination, sustained-load benchmarks, and database partitioning remain future hardening work.

The full interactive web dashboard remains in P2, consistent with the product roadmap decision. Live Suricata/Zeek deployment validation is still pending; see the [technical debt register](docs/technical-debt.md).

## Security

Residential mode trusts the local network and does not authenticate API callers. Keep the Node API on a trusted LAN, restrict access at the network boundary, and never expose port 8000 directly to the Internet. OpenWrt RPC credentials remain separate and must be protected. Store `.env` securely and never commit router credentials or real network event data.

Authentication, authorization, gateway enrollment, and tenant isolation will be introduced before business or SaaS deployment.

## License

License not selected yet.


## P2 — Privacy Intelligence

The interactive web console is served at `http://localhost:8000/`. It combines P1 network visibility and P2 privacy analytics with service onboarding for Pi-hole v6, AdGuard Home, Suricata, and Zeek. DNS provider setup validates live connectivity without importing records; Suricata/Zeek setup displays the push-ingestion endpoint. The console also manages local allow/block lists and explicit provider synchronization. Full integration editing/removal and UI-managed secret storage remain future P2 work.

P2 adds DNS privacy telemetry from Pi-hole and AdGuard Home. OpenShield can poll provider query-log APIs directly or accept bounded pushed JSON batches. Provider credentials are read from environment variables and never stored in integration configuration.

### Register DNS sources

~~~bash
curl -X POST http://localhost:8000/api/v1/integrations \
  -H 'Content-Type: application/json' \
  -d '{"integration_id":"pihole-home","kind":"pihole","display_name":"Pi-hole","config":{"base_url":"http://pihole.lan"}}'

curl -X POST http://localhost:8000/api/v1/integrations \
  -H 'Content-Type: application/json' \
  -d '{"integration_id":"adguard-home","kind":"adguard","display_name":"AdGuard Home","config":{"base_url":"http://adguard.lan"}}'
~~~

### Native polling

~~~bash
curl -X POST http://localhost:8000/api/v1/privacy/sources/pihole-home/sync
curl -X POST http://localhost:8000/api/v1/privacy/sources/adguard-home/sync
~~~

Each sync fetches up to 500 latest provider records. Event IDs make overlapping polls idempotent. Pi-hole without an API password needs no credential. Otherwise set `OPENSHIELD_PIHOLE_PASSWORD`. For AdGuard Home set both `OPENSHIELD_ADGUARD_USERNAME` and `OPENSHIELD_ADGUARD_PASSWORD`. Use HTTPS where available. Do not put credentials in integration config or commit them.

For provider exporters, records can also be pushed to `POST /api/v1/dns/{integration_id}/queries` in batches of up to 500 records and 5 MiB.

### Privacy API

- `GET /api/v1/privacy/sources`: provider ingestion freshness and received query count.
- `POST /api/v1/privacy/sources/{integration_id}/sync`: poll a registered provider.
- `GET /api/v1/privacy/analytics/domains?days=30`: top domains, blocked counts, tracker queries, unique clients.
- `GET /api/v1/privacy/analytics/devices?days=30`: DNS activity grouped by client.
- `GET /api/v1/privacy/trends?days=30`: daily query, blocked, tracker, and unique-domain trends.
- `GET /api/v1/privacy/report?days=30`: summary rates, top domains/clients, and daily trends.
- `GET /api/v1/privacy/lists`, `POST /api/v1/privacy/lists`, `DELETE /api/v1/privacy/lists/{list_type}/{domain}`: locally managed allow/block lists with audit records.

### Classification and enforcement boundaries

Tracker classification uses a small curated suffix set; suspicious-TLD classification is heuristic. These labels are triage hints, not threat-intelligence verdicts. DNS query logs and client identifiers are sensitive browsing metadata. Keep the Node API on the trusted LAN and protect database backups.

Allow/block entries are OpenShield local desired state. They affect providers only after an explicit POST to the provider list sync endpoint. Pi-hole exact allow/deny entries and an OpenShield-managed AdGuard custom-rule section are reconciled and verified; unrelated provider rules are preserved. This is an administrator-triggered configuration write, not automatic enforcement. Keep the unauthenticated Node API restricted to the trusted LAN. Native provider list synchronization and high-volume cursor/watermark pagination are tracked in [Issue #9](https://github.com/squassina/OpenShield/issues/9). Maintained classification feeds are tracked in [Issue #10](https://github.com/squassina/OpenShield/issues/10).


## DNS provider polling

Enabled Pi-hole v6 and AdGuard Home integrations are polled automatically at Node startup and then at the configured interval. The default interval is 60 seconds. Set `OPENSHIELD_DNS_POLL_INTERVAL_SECONDS=0` to disable background polling, or choose a value from 1 to 86400. Provider failures are isolated per integration and recorded in the audit log; duplicate events remain idempotent. The dashboard refreshes its data every 60 seconds while the page is open.


## DNS classification provenance

DNS classifications are descriptive privacy signals, not threat verdicts. OpenShield pins the AdGuard CNAME original-trackers dataset (MIT), and uses it only when the DNS provider supplies an observed CNAME answer; a hostname alone is not enough. It records the upstream commit, source update timestamp, matched target, and confidence with each event. A scheduled workflow checks for feed changes weekly and opens a review PR; it never applies an update automatically. The local suffix/TLD heuristics remain a fallback and carry lower confidence. User overrides (`allow` or `tracker`) take precedence for the matching domain and its subdomains; raw DNS domain, client, timestamp, and response status remain unchanged.


## P3 — Threat intelligence

P3 adds optional CrowdSec CTI and MISP integrations, encrypted provider API keys, bounded on-demand IOC enrichment, a six-hour provider cache, deterministic explainable risk scoring, incident timelines, and audited false-positive/acknowledge/close workflows. See [the threat intelligence runbook](docs/operations/threat-intelligence.md). No P3 finding authorizes network enforcement; P5 owns policy and response.


## P4 — Hybrid AI investigations

P4 adds a local Ollama runtime and an optional OpenAI Responses API adapter. Local inference is the default privacy posture. Cloud use requires both the global `OPENSHIELD_CLOUD_AI_ENABLED=true` switch and an explicit per-integration consent checkbox. Cloud requests contain only aggregate risk factors, event-type/severity counts, and normalized provider reputation categories; they omit indicator values, hostnames, MACs, event IDs, integration IDs, and raw event payloads. AI output is schema-validated, versioned, stored, and audited. Models cannot call tools or execute policy/response actions. See [the AI investigation runbook](docs/operations/ai-investigation.md).


## P5 response engine

OpenShield automatically evaluates deterministic DNS-domain and OpenWrt public-IPv4 response policies after threat-intelligence enrichment, requires human approval for all firewall actions and critical incidents, verifies provider/gateway results, applies TTL-based rollback and provides a global emergency stop. OpenWrt firewall actions require the separately installed least-privilege rpcd plugin. See [the response engine runbook](docs/operations/response-engine.md); physical router validation remains mandatory.
