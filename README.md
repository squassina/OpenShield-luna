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
- Docker Compose development setup.
- Unit/API tests.
- GitHub Actions CI for linting and tests.

### Deliberate P0 limitations

- OpenWrt adapter is a safe stub; authenticated transport is not implemented.
- Registry and events are in-memory; PostgreSQL persistence/migrations remain pending.
- Authentication/RBAC is not enforced. Do not expose this API beyond a trusted development network.
- No gateway credential bootstrap or production mutual authentication exists.
- Durable audit, metrics exporter, reconnect loop, and hardware validation remain pending.
- No firewall or forwarding configuration is changed. The connector is not inline.

### Requirements

Docker Engine + Docker Compose plugin, or Python 3.12+ for local development.

### Run with Docker

```bash
docker compose up --build
```

API: http://localhost:8000  
OpenAPI: http://localhost:8000/docs  
Liveness: http://localhost:8000/health/live  
Readiness: http://localhost:8000/health/ready

### Run locally

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
uvicorn openshield.api.main:app --reload
```

### Test

```bash
cd backend
pytest
```

## API quick start

Register an OpenWrt integration:

```bash
curl -X POST http://localhost:8000/api/v1/integrations \
  -H 'Content-Type: application/json' \
  -d '{"integration_id":"openwrt-lab","kind":"openwrt","display_name":"Lab gateway","config":{"base_url":"https://192.0.2.1"}}'
```

List integrations:

```bash
curl http://localhost:8000/api/v1/integrations
```

Ingest a validated event:

```bash
curl -X POST http://localhost:8000/api/v1/events \
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
| Authentication and RBAC | Pending |
| Durable persistence and audit | Pending |
| Structured logging | Implemented |
| Metrics | Pending |
| Secure connector bootstrap | Pending |
| Disconnect/recovery and real gateway validation | Pending |
| CI and automated tests | Implemented (initial) |

A P0 item is complete only when its exit criteria in PLAN.md are verified. This README is updated with each increment and must not imply production readiness before the remaining security and reliability work is complete.

## Security

Until authentication, RBAC, secure gateway bootstrap, durable audit, and deployment hardening are complete, run only in a trusted development environment. Never commit gateway credentials, API keys, private keys, or real network event data.

## License

License not selected yet.
