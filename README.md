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
- **Deterministic control:** AI recommends; deterministic policy authorizes. P1/P3/P4 do not enforce traffic; P5 is a separate, explicitly opt-in response layer with an emergency stop, TTL, verification, and rollback.
- **Modular monolith:** FastAPI backend with explicit modules and versioned contracts.

See [PLAN.md](PLAN.md) for the product plan, roadmap, architecture decisions, risks, and exit criteria. Disabled integrations reject new event, sensor, and DNS ingestion with HTTP 409; see the [integration enable/disable policy](docs/operations/integration-enable-disable.md).

## Current delivery status

The P0–P6 software baseline is implemented and CI-validated. Remaining open work is operational acceptance, not a claim of completed physical or production validation: OpenWrt hardware and P5 rollback (#17), live Suricata/Zeek deployments (#18), and representative database load/query/restore evidence (#19). See the [engineering TODO](TODO.md) for the prioritized backlog and code-review findings.

## P0 — Foundation & Gateway Connectivity

### Implemented

- FastAPI Node API with liveness/readiness endpoints.
- PostgreSQL-backed integration registry, gateway presence, events, and audit.
- Automatic registration of the gateway integration on first connector handshake.
- Read-only OpenWrt LuCI/ubus client with authenticated session login, bounded HTTP timeout/response size, board/interface/host-hint/DHCP-lease discovery (IPv4 and IPv6), and health check.
- MAC-keyed device inventory with first/last-seen tracking and dashboard grouping by DHCP logical interface (unresolved host hints remain Unmapped).
- Versioned gateway connector contract (`openshield.gateway.v1`).
- Versioned event envelope (`openshield.event.v1`) with validation and provenance.
- Nearby-host Gateway Connector with bounded reconnect behavior.
- Durable SQLite event outbox (10,000-event limit) with persistent Docker volume.
- Automated recovery tests verify offline event collection, spool persistence across recreation, retry-until-acknowledged, and queue drain after Node recovery.
- Idempotent event ingestion; retries do not duplicate stored events or audit entries.
- Durable audit records for integration registration, gateway connection, and event ingestion.
- Prometheus `/metrics` endpoint.
- Docker Compose development environment and GitHub Actions CI.
- The P0 discovery path makes no firewall, routing, wireless, VLAN, DNS, or forwarding changes; P5 enforcement is separate and explicitly opt-in.

### Current residential API behavior

The default residential profile keeps admin API authentication disabled. Optional HTTP Basic authentication protects the dashboard and administrative API when `OPENSHIELD_API_AUTH_ENABLED=true`. UI-managed router credentials require a separate `OPENSHIELD_GATEWAY_TOKEN` shared by Node and connector; it is not an admin API key.

The connector defaults to gateway ID `home-gateway`. On its first `POST /api/v1/gateway/connect`, the Node creates an OpenWrt integration with the same ID. Heartbeats include the gateway ID. Discovery and health events use that ID as their source. Discovery runs on every heartbeat and updates the MAC-keyed device inventory; the dashboard groups online/offline devices by logical router interface.

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
- P0 OpenWrt discovery is read-only and does not modify router configuration. Separate P5 enforcement can add or remove narrowly scoped temporary UCI firewall rules through authenticated gateway commands after explicit policy approval. It is disabled by default and requires physical firmware, ACL, and rollback validation before use.
- PostgreSQL uses versioned schema migrations and a bounded connection pool. Verified custom-format backup and fail-closed restore scripts are included; CI exercises a real PostgreSQL backup/restore round-trip. Deployment-specific backup retention, off-host encryption, staging recovery evidence, and production database hardening remain operational responsibilities.
- Audit retention, tamper-evidence, and external immutable export remain pending.
- Metrics are process-local and reset on restart.
- The connector is a nearby-host Linux/Docker agent, not an on-device OpenWrt daemon.
- Physical OpenWrt hardware/firmware compatibility and forwarding-independence validation remain open in [Issue #17](https://github.com/squassina/OpenShield-luna/issues/17).

## PostgreSQL backup and restore

Custom-format database backups use [`scripts/backup.sh`](scripts/backup.sh). The script writes to a unique temporary file, validates the archive with `pg_restore --list`, restricts permissions to the owner, and publishes it with an atomic rename. Failed or interrupted dumps do not leave a partial file under the final backup name.

Restores use [`scripts/restore.sh`](scripts/restore.sh). The script requires `OPENSHIELD_RESTORE_CONFIRM=YES`, validates the archive, refuses targets containing user database objects, and restores in one PostgreSQL transaction. It does not drop or truncate an existing database. Restore only into a newly created, isolated database.

The CI workflow runs a real `pg_dump`/`pg_restore` round-trip between disposable PostgreSQL databases and verifies schema migrations and exact table counts. This validates the scripts and verifier, not a deployment's actual backup media or recovery objectives.

Backups contain sensitive network metadata and configuration. Encrypt them at rest, store copies outside the database volume, and protect the database credentials and `OPENSHIELD_SECRET_KEY` separately. See the [event load, query-plan and backup/restore runbook](docs/operations/event-load-backup.md) for the complete procedure. Staging load measurements, query-plan review and a restore drill using deployment data remain open under [Issue #19](https://github.com/squassina/OpenShield-luna/issues/19).

## Docker-first development

Docker Engine and the Docker Compose plugin are the only local runtime/test prerequisites. Compose starts PostgreSQL 16 with a named persistent volume; Python, Ruff, and Pytest do not need to be installed on the host.

1. Copy `.env.example` to `.env`.
2. Set a local PostgreSQL password and keep `OPENSHIELD_DATABASE_URL` in sync.
3. Build and start the API:

```bash
docker compose up --build -d openshield-node
```

The Node and Gateway Connector runtime images run as UID/GID 10001 (`openshield`). The image pre-creates the runtime-secrets and gateway-spool mount points with ownership restricted to this user. New named volumes inherit these permissions.

If upgrading an installation whose named volumes were created by an older root-based image, migrate ownership once **before** starting the new runtime:

```bash
docker compose build openshield-node openshield-gateway-connector
docker compose run --rm --no-deps --user 0:0 --entrypoint sh openshield-node \
  -c 'chown -R 10001:10001 /run/openshield-secrets && chmod 0700 /run/openshield-secrets'
```

If the Gateway Connector profile is used, also migrate its spool volume:

```bash
docker compose --profile gateway run --rm --no-deps --user 0:0 --entrypoint sh openshield-gateway-connector \
  -c 'chown -R 10001:10001 /run/openshield-secrets /var/lib/openshield && chmod 0700 /run/openshield-secrets /var/lib/openshield'
```

These one-time commands run only the migration shell as root; the long-running Node and Connector processes remain unprivileged. Secret files retain their existing restrictive modes.

Run lint and tests in the same Python 3.12 container environment used by CI:

```bash
docker compose build openshield-test openshield-lint
docker compose run --rm openshield-lint
docker compose run --rm openshield-test

# Browser-level dashboard tests (Chromium)
# Uses the official Playwright Python image with Chromium and OS libraries preinstalled.
# Do not run Playwright's --with-deps or apt-get browser setup in CI:
# those steps depend on Ubuntu mirror DNS and have failed on hosted runners.
docker compose build openshield-browser-test
docker compose run --rm openshield-browser-test
```

See the [dashboard browser test runbook](docs/operations/dashboard-browser-tests.md) for the CI image rationale and troubleshooting.

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
- `OPENSHIELD_GATEWAY_SPOOL_PATH` (default `/var/lib/openshield/gateway-spool.sqlite3`)
- `OPENSHIELD_OPENWRT_URL`, `OPENSHIELD_OPENWRT_USERNAME`, `OPENSHIELD_OPENWRT_PASSWORD` (legacy environment-based fallback; prefer dashboard setup)

For dashboard-managed credentials, set `OPENSHIELD_SECRET_KEY` on Node and the same `OPENSHIELD_GATEWAY_TOKEN` on Node and connector. Enter the router URL, RPC username, and password in the dashboard; the connector receives the encrypted-at-rest configuration after authentication. The legacy OpenWrt environment variables remain supported but are not required for ordinary setup. Use HTTPS for Node/connector traffic outside a trusted isolated network. For safe Fernet key rotation, configure `OPENSHIELD_SECRET_KEY_PREVIOUS` on Node and follow the [secret key rotation runbook](docs/operations/secret-key-rotation.md).

Start the optional connector profile:

```bash
docker compose --profile gateway up --build -d openshield-node openshield-gateway-connector
docker compose logs -f openshield-gateway-connector
```

The connector is outbound-only and does not sit in the packet-forwarding path. When the Node is unavailable, it continues local collection and queues events in SQLite. Events are removed from the spool only after the Node acknowledges them. The queue is bounded at 10,000 events. At capacity, it evicts the oldest unprotected low-priority event first; gateway health, command results, security/audit events, and high/critical-severity events are protected. Identical health snapshots may be coalesced, but health-state transitions remain durable. If all queued events are protected and no identical health snapshot can be compacted, the incoming event is rejected and a durable dropped counter is incremented. SQLite uses WAL and FULL synchronous mode; the database file is mode 0600 and its directory mode 0700. The spool is not encrypted at rest, so protect the host and Docker volume. Its durable counters are not yet exposed as metrics or alerts.

## OpenWrt read-only discovery

For physical gateway testing, outage/restart drills, and acceptance evidence, follow [the OpenWrt P0 validation runbook](docs/operations/openwrt-validation.md).

The OpenWrt account should have only read access to `session.login`, `system.board`, `network.interface.dump`, `luci-rpc.getHostHints`, and `luci-rpc.getDHCPLeases`. Reuse the existing LuCI ACL groups; do not install packages, scripts, or ACL files on the router. Never grant `file.exec` or write permissions. Use HTTPS where supported. For HTTP-only management, isolate the management network because credentials are not encrypted in transit.

The P0 discovery flow does not change firewall, routing, wireless, VLAN, DNS, or forwarding settings. The separate P5 policy path can make tightly scoped temporary firewall changes only after explicit authorization; real hardware compatibility and rollback remain unverified until tested against supported firmware.

## API quick reference

The administrative API is unauthenticated by default in residential mode. If Basic authentication is enabled, use the browser's HTTP Basic prompt or pass `-u user:password` to curl. Gateway routes use the connector bearer token; Suricata/Zeek ingestion requires the corresponding per-sensor bearer token. Examples:

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
| OpenWrt ubus adapter, board/interface discovery, health check | Implemented (connector-side read-only; physical validation tracked in #17) |
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

P0 software scope is complete and CI-validated. Physical OpenWrt compatibility and forwarding-independence validation remain open in [Issue #17](https://github.com/squassina/OpenShield-luna/issues/17); this does not block the P0 software closeout.

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

Issue a per-sensor bearer credential. The token is returned only once; OpenShield stores only its SHA-256 digest encrypted at rest. Rotation invalidates the previous token, and deletion revokes it:

```bash
curl -X PUT http://localhost:8000/api/v1/sensors/suricata-home/credentials
curl -X PUT http://localhost:8000/api/v1/sensors/zeek-home/credentials
```

Save each returned `token` securely in the corresponding sensor's secret store. Send EVE records or Zeek JSON records as a JSON array with that sensor's token:

```bash
curl -X POST http://localhost:8000/api/v1/sensors/suricata-home/events \
  -H 'Authorization: Bearer <SURICATA_SENSOR_TOKEN>' \
  -H 'Content-Type: application/json' \
  --data-binary @eve-batch.json

curl -X POST http://localhost:8000/api/v1/sensors/zeek-home/events \
  -H 'Authorization: Bearer <ZEEK_SENSOR_TOKEN>' \
  -H 'Content-Type: application/json' \
  --data-binary @zeek-batch.json
```

The credential is scoped to one integration. It cannot ingest events for another sensor. Both the sensor batch endpoint and generic `POST /api/v1/events` enforce the sensor credential for Suricata/Zeek sources. Revoke with `DELETE /api/v1/sensors/{integration_id}/credentials`.

### Network visibility API

- `GET /api/v1/inventory/devices`: observed, validated IP addresses, IP version/scope, protocols, first/last seen, and observation counts. Invalid, unspecified, and multicast addresses are excluded.
- `GET /api/v1/inventory/topology`: observed source-to-destination edges, protocol counts, and inferred direction (`internal`, `outbound`, `inbound`, `external`, or `other`). This is not an authoritative physical topology.
- `GET /api/v1/sensors`: sensor ingestion freshness based on the Node-generated `observed_at` timestamp (healthy within five minutes, stale afterward, or no_data). This confirms recent delivery to OpenShield, not sensor process or packet-capture health.
- `GET /api/v1/events?integration_id=...&event_type=...&severity=...&limit=...&cursor=...`: filtered event exploration with keyset cursor pagination. Filters, ordering, and limits execute in PostgreSQL.

Sensor ingestion always requires a per-sensor bearer credential, including in residential mode. Rotate/revoke credentials through `/api/v1/sensors/{integration_id}/credentials`; when Business admin authentication is enabled, these operations require the administrator's HTTP Basic credentials. Keep port 8000 behind a trusted network boundary; do not expose it directly to the Internet. Configure Suricata/Zeek to send only the records needed for visibility. The P1 APIs do not block traffic or change gateway configuration.

Inventory and topology use database-side aggregation; the API does not load the full raw event history to calculate these views. Stable keyset cursor pagination and opt-in batched retention are implemented. A sequential synthetic ingestion benchmark, read-only query-plan diagnostics, restore-manifest verifier, and disposable PostgreSQL backup/restore drill are included. Representative load, query-plan/index evaluation, and restore against deployment data remain open in [Issue #19](https://github.com/squassina/OpenShield-luna/issues/19); partitioning should be considered only if measurements justify it.

The interactive dashboard and P2 privacy-intelligence software are implemented. Live Suricata/Zeek deployment validation remains pending in [Issue #18](https://github.com/squassina/OpenShield-luna/issues/18); physical gateway and database operational acceptance remain tracked in [TODO.md](TODO.md).

## Security

Residential mode trusts the local network for administrative API access and keeps optional HTTP Basic authentication disabled by default. Suricata/Zeek ingestion is always protected by a per-sensor bearer token. Keep the Node API on a trusted LAN, restrict access at the network boundary, and never expose port 8000 directly to the Internet. OpenWrt RPC credentials remain separate and must be protected. Store `.env` securely and never commit router credentials or real network event data.

Integration-scoped sensor bearer credentials, gateway bearer authentication, and optional shared-admin HTTP Basic authentication are implemented. User identity, per-user RBAC, organization/site ownership, and tenant isolation are not; they remain mandatory design and implementation gates before shared Business or SaaS use.

## License

No `LICENSE` file is present; the project license remains undecided.


## P2 — Privacy Intelligence

The interactive web console is served at `http://localhost:8000/`. It combines network visibility and privacy analytics with service onboarding for Pi-hole v6, AdGuard Home, Suricata, and Zeek. DNS provider setup validates live connectivity without importing records; Suricata/Zeek setup displays the push-ingestion endpoint. The console supports integration editing and deletion, local allow/block lists, and explicit provider synchronization. Supported integration credentials are stored through the encrypted secret store, not in integration configuration or API responses.

DNS privacy telemetry supports Pi-hole and AdGuard Home. OpenShield polls provider query-log APIs directly or accepts bounded pushed JSON batches. Credentials are stored encrypted per integration and never in integration configuration; legacy environment-variable fallbacks remain supported.

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

Each sync fetches up to 500 latest provider records. Event IDs make overlapping polls idempotent. Pi-hole without an API password needs no credential. Otherwise configure its password in the dashboard; AdGuard Home requires a username and password. Dashboard credentials are encrypted at rest per integration. Legacy fallbacks are `OPENSHIELD_PIHOLE_PASSWORD`, `OPENSHIELD_ADGUARD_USERNAME`, and `OPENSHIELD_ADGUARD_PASSWORD`. Use HTTPS where available. Never put credentials in integration config or commit them. For private PKI, mount CA PEM bundles in `./certs` and set `ca_bundle_path` on each DNS integration (for example, `/run/openshield/ca/pihole-ca.pem`). This adds that CA to the system trust roots for that integration only; certificate-chain and hostname verification stay enabled. See the [DNS provider TLS runbook](docs/operations/dns-provider-tls.md).

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

Tracker classification uses the pinned AdGuard CNAME tracker feed when the provider supplies an observed CNAME answer, with curated suffixes as a fallback; suspicious-TLD classification is heuristic. These labels are triage hints, not threat-intelligence verdicts. DNS query logs and client identifiers are sensitive browsing metadata. Keep the Node API on the trusted LAN and protect database backups.

Allow/block entries are OpenShield local desired state. They affect providers only after an explicit POST to the provider list sync endpoint. Pi-hole exact allow/deny entries and an OpenShield-managed AdGuard custom-rule section are reconciled and verified; unrelated provider rules are preserved. This is an administrator-triggered configuration write, not automatic enforcement. Keep the residential administrative API restricted to the trusted LAN. Native provider-list synchronization, durable cursors/watermarks, bounded pagination, and reviewed classification-feed updates are implemented. Polling processes one provider page per integration per cycle, so backlog catch-up depends on the configured interval. The remaining operational performance validation is tracked in [Issue #19](https://github.com/squassina/OpenShield-luna/issues/19).


## DNS provider polling

Enabled Pi-hole v6 and AdGuard Home integrations are polled automatically at Node startup and then at the configured interval. The default interval is 60 seconds. Set `OPENSHIELD_DNS_POLL_INTERVAL_SECONDS=0` to disable background polling, or choose a value from 1 to 86400. Polling processes one provider page per cycle. Valid events are inserted idempotently; malformed records are isolated, counted, and recorded in the audit log with sanitized reason codes and bounded record indexes (never raw DNS/client values). The provider cursor advances only after valid events and rejection diagnostics are durably recorded. If persistence fails, the cursor remains unchanged and the page is retried; duplicate event IDs prevent duplicate ingestion. Provider failures are isolated per integration. The dashboard refreshes its data every 60 seconds while the page is open. See the [DNS polling failure runbook](docs/operations/dns-polling-failures.md) for error categories, per-integration metrics, and cursor guarantees.


## DNS classification provenance

DNS classifications are descriptive privacy signals, not threat verdicts. OpenShield pins the AdGuard CNAME original-trackers dataset (MIT), and uses it only when the DNS provider supplies an observed CNAME answer; a hostname alone is not enough. It records the upstream commit, source update timestamp, matched target, and confidence with each event. A scheduled workflow checks for feed changes weekly and opens a review PR; it never applies an update automatically. The local suffix/TLD heuristics remain a fallback and carry lower confidence. User overrides (`allow` or `tracker`) take precedence for the matching domain and its subdomains; raw DNS domain, client, timestamp, and response status remain unchanged.

## P3 — Threat intelligence

P3 implements optional CrowdSec CTI and MISP integrations, encrypted provider API keys, bounded on-demand IOC enrichment, a six-hour provider cache, deterministic explainable risk scoring, incident timelines, and audited false-positive/acknowledge/close workflows. See [the threat intelligence runbook](docs/operations/threat-intelligence.md). No P3 finding authorizes network enforcement; P5 owns policy and response.

## pfSense CE read-only integration

OpenShield can connect to pfSense Community Edition through the **community-maintained pfSense REST API v2 package** ([documentation](https://pfrest.org/)). This package is not built into pfSense CE. An administrator must install and configure it separately, enable API-key authentication, and grant only the read privileges required by the selected endpoints. OpenShield never installs packages or changes pfSense configuration.

In the dashboard, add a **pfSense CE firewall** integration with its HTTPS base URL and API key. OpenShield encrypts the key at rest using \`OPENSHIELD_SECRET_KEY\`; the key is not stored in integration configuration or returned by the API. The connector sends the key in the \`X-API-Key\` header and performs GET requests only.

Read-only diagnostics currently query:

- \`GET /api/v2/status/system\`
- \`GET /api/v2/status/interfaces\`
- \`GET /api/v2/diagnostics/arp_table\`
- \`GET /api/v2/status/dhcp_server/leases\`
- \`GET /api/v2/status/gateways\`

The REST API package must expose these endpoints for the installed version and the API key's user must have corresponding read privileges. Use HTTPS with a trusted certificate. The integration does not create firewall rules, apply configuration, restart services, or install/upgrade the pfSense API package.


## Wazuh read-only integration

OpenShield connects to the Wazuh Server API with a dedicated API user and reads manager metadata/status plus up to 500 agent records. Credentials are encrypted at rest. The connector uses POST only for JWT login and GET for diagnostics; it does not modify Wazuh. Use a least-privilege account (the built-in `readonly` role or equivalent) and a TLS certificate trusted by the OpenShield Node. See [Wazuh integration setup](docs/operations/wazuh.md).

Grafana read-only integration setup: [docs/operations/grafana.md](docs/operations/grafana.md).

## P4 — Hybrid AI investigations

P4 implements a local Ollama runtime and an optional OpenAI Responses API adapter. Local inference is the default privacy posture. Cloud use requires both the global `OPENSHIELD_CLOUD_AI_ENABLED=true` switch and an explicit per-integration consent checkbox. Cloud requests contain only aggregate risk factors, event-type/severity counts, and normalized provider reputation categories; they omit indicator values, hostnames, MACs, event IDs, integration IDs, and raw event payloads. AI output is schema-validated, versioned, stored, and audited. Models cannot call tools or execute policy/response actions. See [the AI investigation runbook](docs/operations/ai-investigation.md).


## P6 — Enterprise Readiness Baseline

- Multiple gateway IDs are independently tracked by the Node; see `GET /api/v1/gateways`.
- Bounded operational summary is available at `GET /api/v1/reports/operations`.
- PostgreSQL custom-format backup and restore helpers are in `scripts/`. Restore requires explicit confirmation and an operator-supplied fresh, empty target database; the script does not yet preflight target emptiness (see TODO.md).
- Compose publishes the API on loopback by default; set `OPENSHIELD_PUBLISH_ADDRESS` to the Node's trusted-LAN address when remote LAN clients need access.
- Deployment and recovery guidance: [Enterprise readiness runbook](docs/operations/enterprise-readiness.md).

This baseline does not implement multi-tenancy, RBAC, or a centralized multi-Node control plane. Do not use one Node for mutually untrusted organizations.

## P5 — Policy and bounded response

P5 implements exact-indicator policies, autonomy levels L0–L3, human approval, an emergency stop, DNS block-list execution, and temporary OpenWrt firewall rules delivered through the authenticated Gateway Connector. Enforcement remains disabled by default; the emergency stop is active and the global autonomy cap is L0 by default. Actions have a maximum 24-hour TTL with automatic rollback and audit. See [the P5 response runbook](docs/operations/policy-response.md). Physical router validation is required before enabling enforcement.
