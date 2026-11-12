# OpenShield — Product & Technical Plan

**Product:** OpenShield — Autonomous Network Security & Privacy Intelligence  
**Document:** Product and Technical Plan  
**Version:** 0.2  
**Status:** Initial baseline  
**Deployment philosophy:** Self-hosted first, gateway-first, local-first AI, policy-driven autonomy

---

## 1. Executive Summary

OpenShield is an open-source, self-hosted platform for network security and privacy intelligence. It connects to existing network and security tools, collects and normalizes their signals, correlates events into incidents, assesses risk, explains findings, and can execute narrowly authorized responses.

OpenShield is **not** intended to replace every firewall, DNS resolver, IDS, or SIEM. Its differentiator is the integration and intelligence layer across tools that already exist, with controlled and auditable action.

The first deployment model is **Gateway-first**: a lightweight connector runs on or alongside a supported gateway, while the OpenShield Node runs on a separate Linux server, mini PC, or VM. The gateway must continue forwarding traffic when the Node is unavailable. OpenShield must not become an inline single point of failure.

AI is **hybrid and local-first**. Local inference is the default. Cloud AI is optional, explicitly configured, and receives only minimized and sanitized context. AI can investigate and recommend; deterministic policy and execution components govern all actions.

## 2. Vision and Product Positioning

### 2.1 Vision

Give home power users and small businesses a coherent, explainable view of network security and privacy, using their existing tools and infrastructure, with safe automation under their control.

### 2.2 Positioning

**OpenShield — Autonomous Network Security & Privacy Intelligence**

The platform provides:
- Integration across existing network, DNS, IDS, threat-intelligence, and firewall tools.
- Device and service discovery, with manual configuration as a fallback.
- Event normalization, correlation, risk assessment, and incident timelines.
- Evidence-grounded investigation and explanations using local AI by default.
- Policy-governed response with authorization, verification, audit, and rollback where supported.

OpenShield is an intelligence and orchestration layer—not a new IDS, DNS resolver, firewall, or generic SIEM.

### 2.3 Target Users

1. **Home / Advanced Users:** self-hosters and technically capable users who want visibility, privacy insight, and safe automation.
2. **Business / SMB:** small organizations that need understandable security posture and controlled response without a large security operations team.

The architecture should allow later expansion to multiple sites and gateways without making enterprise complexity a prerequisite for the MVP.

## 3. Scope

### 3.1 In Scope

- Self-hosted deployment.
- Gateway connector and OpenShield Node architecture.
- Integration Hub and adapter SDK.
- Automatic discovery where supported, plus explicit manual setup.
- Network device inventory and topology.
- Ingestion and normalization of events from supported tools.
- Incident correlation, timelines, and risk assessment.
- Privacy and DNS intelligence.
- Local-first AI investigation and optional cloud second opinion.
- Deterministic policies and bounded response execution.
- Verification, audit trails, TTLs, rollback where supported, and emergency stop.
- Home and Business operating profiles.

### 3.2 Explicitly Out of Scope

- SMTP or mail-server hosting.
- Anti-spam platform.
- Endpoint antivirus.
- Mandatory endpoint agents.
- Mandatory app-level integrations.
- General HTTPS content inspection or TLS interception.
- Claims to detect encrypted prompt/content semantics without suitable instrumentation.
- Replacing mature tools such as firewalls, DNS resolvers, IDS engines, or SIEM platforms.

## 4. Planning Framework

Product decisions will follow this sequence:

1. **Diagnóstico:** define the problem, users, constraints, and success criteria.
2. **Gerar Opções:** identify viable approaches and alternatives.
3. **Análise Trade-offs:** compare security, complexity, reliability, privacy, and operational cost.
4. **Recomendação Acionável:** select a direction, record the rationale, and turn it into implementation work.

Material architecture decisions should be recorded as Architecture Decision Records (ADRs).

## 5. Diagnosis and Requirements

### 5.1 Problem

Network security and privacy signals are fragmented across gateways, DNS tools, IDS engines, threat-intelligence sources, and dashboards. Users must correlate these signals manually, interpret risks, and perform actions across separate systems.

OpenShield should reduce this fragmentation while preserving the strengths of the tools already deployed.

### 5.2 Product Requirements

- Connect to supported gateways using an authenticated, least-privilege connector.
- Discover available integrations and capabilities when possible.
- Support manual integration configuration when discovery is unavailable or ambiguous.
- Normalize events into a versioned common schema.
- Preserve source identity and provenance for every event and finding.
- Correlate related observations into incidents.
- Explain risk and recommendations with links to underlying evidence.
- Require deterministic policy authorization before any action.
- Record decisions, approvals, execution results, verification, and rollback.
- Remain useful when optional AI or cloud services are unavailable.

### 5.3 Non-Functional Requirements

- **Fail-safe gateway behavior:** the gateway keeps forwarding traffic if the Node fails.
- **Security by design:** authenticated communication, least privilege, secrets protection, secure defaults, and auditable access.
- **Privacy by design:** data minimization, local-first processing, explicit cloud opt-in, and configurable retention.
- **Explainability:** findings and actions must be traceable to evidence and policy.
- **Reliability:** event ingestion should tolerate transient failures and recover without silently losing critical events.
- **Extensibility:** adapters and event schemas must be versioned and documented.
- **Operability:** health checks, structured logs, metrics, backup/restore, and clear diagnostics.
- **Testability:** unit, integration, security, and end-to-end tests for safety-critical flows.

## 6. Architecture Decisions

### 6.1 Deployment: Gateway-first

**Selected approach:** Gateway Connector + OpenShield Node.

- The **Gateway Connector** is a lightweight adapter deployed on the gateway when feasible, or on a nearby host when not. It exposes only supported, authorized capabilities.
- The **OpenShield Node** runs the core services, event pipeline, database, API, dashboard, and local AI runtime on a separate Linux server, mini PC, or VM.
- The gateway remains operational independently of the Node.
- A passive sensor or mirrored-traffic mode may be added as an alternative or complementary deployment mode.

Do not make the Node an inline forwarding dependency.

### 6.2 Integration Strategy: Hybrid Discovery and Manual Setup

Use automatic discovery when the integration provides a trustworthy mechanism. Use manual setup for unsupported discovery, ambiguous results, or explicit administrator preference.

The Integration Hub and adapter SDK should expose capability-based contracts, where applicable:

- `discover`
- `health_check`
- `read_events`
- `read_configuration`
- `write_configuration`
- `execute_action`
- `verify_action`

Capabilities are optional per adapter. A passive sensor may read events but never enforce. An enforcement adapter may execute actions without deep telemetry. OpenShield must not assume universal capabilities or guess credentials.

### 6.3 AI Strategy: Hybrid, Local-first

- Local inference is the default for routine investigations, correlation context, explanations, summaries, and recommendations.
- Cloud AI is optional and disabled unless explicitly configured.
- Cloud requests must be minimized and sanitized.
- Raw PCAP, credentials, internal identifiers, and sensitive information are excluded from cloud requests by default.
- AI is not an execution authority. A deterministic Policy Engine decides whether an action is allowed.
- Cloud or Internet outages must not stop deterministic protections and already-authorized local responses.

### 6.4 Autonomy and Safety Model

Use explicit autonomy levels:

| Level | Name | Behavior |
|---|---|---|
| L0 | Observe | Collect, correlate, and report; no enforcement |
| L1 | Low-impact authorized protection | Automatically apply explicitly pre-authorized, low-impact actions |
| L2 | Bounded containment | Contain within narrow, pre-approved policies and limits |
| L3 | Human approval required | Critical, broad, or high-impact changes require explicit approval |

Every supported automated action must define:
- Scope and target.
- Policy that authorizes it.
- Maximum impact and duration.
- Time-to-live (TTL), where meaningful.
- Verification procedure.
- Rollback procedure, where supported.
- Audit record.
- Emergency stop / kill switch behavior.

An action that cannot be verified or safely bounded should not be automated by default.

### 6.5 Event Architecture

Start with a **modular monolith and asynchronous event processing**, not premature microservices or Kubernetes.

The event pipeline should support:
1. Source adapter ingestion.
2. Validation and schema versioning.
3. Normalization with provenance.
4. Durable persistence.
5. Correlation and enrichment.
6. Incident and risk generation.
7. Policy evaluation.
8. Optional execution and verification.

Use a queue or broker only when justified by measured reliability, throughput, or isolation needs. Avoid introducing Redis solely by default.

## 7. Reference Architecture

### 7.1 Logical Components

**Gateway side**
- Gateway Connector.
- OpenWrt / firewall4 / nftables adapter as the initial target.
- Unauthenticated residential Node/connector communication using the versioned `openshield.gateway.v1` contract; restrict API access to the trusted home LAN.
- Stable local gateway identity, read-only capability advertisement, automatic first-connect registration, and heartbeat presence.
- Minimal local state and safe behavior when disconnected.

**OpenShield Node**
- Residential API without user accounts or API credentials; business authentication and authorization are deferred.
- Integration Registry and Adapter SDK.
- Discovery and configuration service.
- Event ingestion and normalization.
- Device inventory and topology.
- Correlation and Risk Engine.
- Incident management and timeline.
- Policy Engine.
- Execution Engine.
- AI Orchestrator and privacy gateway.
- Local model runtime integration.
- Audit, telemetry, and health monitoring.
- Web dashboard.
- PostgreSQL persistence.

### 7.2 Candidate Open-Source Integrations

These are candidates to validate, not mandatory dependencies or final commitments.

| Domain | Candidate | Potential role |
|---|---|---|
| Gateway / firewall | OpenWrt firewall4, nftables | Gateway connectivity and enforcement |
| Network IDS | Suricata | Network threat and protocol alerts |
| Network analytics | Zeek | Network metadata and behavioral context |
| Threat intelligence | CrowdSec, MISP | Reputation, community signals, IOC feeds |
| DNS privacy | Pi-hole, AdGuard Home, Blocky | DNS events, filtering, privacy insights |
| Recursive DNS | Unbound | Optional resolver integration |
| Endpoint / host telemetry | Wazuh | Optional source; never mandatory |
| Metrics | Prometheus | Metrics collection |
| Dashboards | Grafana | Optional operational visualization |
| Local AI runtime | Ollama or llama.cpp | Local model inference |
| Backend | Python 3.12+ / FastAPI | API and core services |
| Frontend | React / TypeScript | Web dashboard |
| Persistence | PostgreSQL | Durable state, events, incidents, audit |
| Deployment | Docker Compose | Initial self-hosted deployment |
| CI/CD | GitHub Actions | Automated validation and delivery |
| Testing | Pytest, integration/security tests, Playwright | Quality and safety validation |

Final choices should be made after P0/P1 validation, not assumed from this candidate list.

## 8. AI Operating Model and Governance

### 8.1 Local AI

Local inference should handle ordinary investigations and explanations using evidence already stored by OpenShield. Outputs must distinguish observed facts, inferred hypotheses, confidence, and recommended next steps.

### 8.2 Optional Cloud AI

Cloud providers should be accessed through a provider abstraction. Cloud use requires explicit configuration and policy. Before sending data:
- Minimize the request to the specific question.
- Sanitize or remove identifiers and secrets.
- Exclude raw packet captures by default.
- Record provider, purpose, and data categories sent.
- Respect tenant/user configuration and retention policies.

### 8.3 AI Security

Treat event contents, device names, DNS records, logs, and external threat-intelligence text as untrusted input. They may contain prompt-injection attempts.

The AI Orchestrator must:
- Separate instructions from evidence.
- Prevent tool output from changing system policy.
- Ground claims in stored evidence.
- Avoid granting AI direct execution credentials.
- Return structured recommendations for deterministic policy evaluation.
- Log model and prompt-template versions for audit and evaluation.

## 9. Technology Strategy

### 9.1 Initial Engineering Shape

- Modular monolith for core business capabilities.
- Asynchronous event pipeline with durable persistence.
- Adapter contracts for external tools.
- Versioned event schema.
- React / TypeScript frontend.
- Python / FastAPI backend.
- PostgreSQL as primary data store.
- Docker Compose for initial deployment.

### 9.2 Engineering Principles

- Secure defaults and least privilege.
- Explicit configuration; no credential guessing.
- Fail-safe gateway connectivity.
- Idempotent integration operations where feasible.
- Bounded retries and clear dead-letter/error handling.
- Versioned APIs, schemas, and adapters.
- Observable operations without leaking secrets.
- Tests for failure modes, authorization boundaries, rollback, and audit integrity.
- Keep dependencies and operational burden proportional to the validated need.

## 10. Roadmap

### P0 — Foundation & Gateway Connectivity

**Goal:** establish a secure, testable foundation and prove connectivity to the first supported gateway.

Scope:
- Repository conventions and architecture documentation.
- Docker Compose development environment.
- Trusted-LAN residential API and automatic gateway enrollment.
- Gateway Connector protocol.
- Initial OpenWrt adapter.
- Integration Registry and Adapter SDK.
- Capability model.
- Discovery plus manual configuration fallback.
- Versioned event schema and normalizer.
- Audit foundation.
- Health checks, structured logging, metrics, and CI.
- Unit and integration tests.
- Node/gateway disconnection and recovery behavior.

**Exit criteria:** OpenShield Node can establish a secure connection to a supported gateway, discover its declared capabilities, and ingest at least one validated event from an initial integration. Gateway forwarding remains unaffected when the Node is stopped.

### P1 — Network Visibility

**Goal:** provide useful visibility into devices and network activity.

Scope:
- Device discovery and inventory.
- Network topology.
- Suricata integration.
- Zeek integration.
- Connection and protocol metadata.
- Initial dashboard and event exploration.
- Sensor and integration health.

### P2 — Privacy Intelligence

**Goal:** make DNS activity and privacy risks understandable.

Scope:
- Pi-hole integration.
- AdGuard Home integration.
- DNS analytics and device/domain views.
- Tracker and suspicious-domain classification.
- Block/allow list integration capabilities.
- Privacy reports and trends.

### P3 — Threat Intelligence & Risk Engine

**Goal:** correlate network observations with threat intelligence and produce explainable incidents.

Scope:
- CrowdSec integration.
- MISP integration.
- Reputation and IOC correlation.
- Risk scoring with documented factors.
- Incident timeline and investigation workflow.
- Evidence provenance and false-positive handling.

### P4 — Hybrid AI Network Intelligence

**Goal:** provide evidence-grounded investigation and recommendations.

Scope:
- AI provider abstraction.
- Local runtime integration.
- Optional cloud provider adapters.
- AI Orchestrator and privacy gateway.
- Evidence-grounded incident investigation.
- Explanations, summaries, and recommendations.
- AI governance, evaluation, and prompt-injection resilience.

### P5 — Autonomous Response

**Goal:** safely execute bounded, authorized network responses.

Scope:
- Policy Engine and policy management.
- Execution Engine.
- Gateway, firewall, and DNS enforcement adapters.
- Autonomy levels L0–L3.
- TTL and automatic expiration.
- Verification and rollback.
- Human approval workflow.
- Emergency stop / kill switch.
- Complete decision and execution audit.

### P6 — Enterprise Readiness

**Goal:** support broader operational use where validated by demand.

Scope:
- Multiple gateways and sites.
- Multi-tenancy if justified by validated requirements.
- Home and Business profiles.
- Centralized management.
- Reports and operational summaries.
- Backup and recovery.
- Deployment hardening and security review.

## 11. MVP Definition and Acceptance Criteria

The MVP should demonstrate the complete intelligence-and-control loop without requiring cloud AI or broad autonomous enforcement.

Acceptance criteria:
1. Deploy OpenShield Node using documented self-hosted instructions.
2. Connect securely to one supported gateway.
3. Discover gateway capabilities and at least one network integration, with manual setup as fallback.
4. Discover and display network devices from supported sources.
5. Ingest real events from at least two independent sources.
6. Validate and normalize events into the versioned common schema.
7. Correlate related events into at least one incident.
8. Run a local AI investigation grounded in persisted evidence.
9. Show evidence, uncertainty, and recommendations distinctly.
10. Evaluate a deterministic policy for a proposed test response.
11. Execute only an explicitly authorized test action.
12. Verify the action and demonstrate rollback or expiration where supported.
13. Record the full decision and execution trail in the audit log.
14. Demonstrate that gateway traffic forwarding continues when the Node is unavailable.
15. Demonstrate that cloud AI is unnecessary for the MVP and remains disabled by default.

## 12. Proposed Repository Structure

The structure is a starting point and may evolve as implementation validates module boundaries.

```text
OpenShield/
├── PLAN.md
├── README.md
├── LICENSE
├── SECURITY.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── docs/
│   ├── architecture/
│   │   ├── overview.md
│   │   └── decisions/
│   ├── development/
│   ├── operations/
│   └── security/
├── deploy/
│   └── docker-compose/
├── gateway/
│   └── connectors/
├── backend/
│   ├── api/
│   ├── core/
│   ├── integrations/
│   ├── events/
│   ├── inventory/
│   ├── incidents/
│   ├── risk/
│   ├── policies/
│   ├── execution/
│   ├── ai/
│   └── audit/
├── frontend/
├── schemas/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── security/
│   └── e2e/
└── .github/
    └── workflows/
```

## 13. Architecture Decision Records

The following ADRs should be created as implementation begins. Their decisions are summarized here to keep the baseline explicit.

| ADR | Decision | Status |
|---|---|---|
| ADR-001 | Gateway Connector + separate OpenShield Node; gateway forwarding must not depend on Node availability | Accepted |
| ADR-002 | Hybrid integration: authorized discovery plus manual configuration; capability-based adapters | Accepted |
| ADR-003 | Hybrid AI, local-first; cloud optional and explicitly enabled | Accepted |
| ADR-004 | Modular monolith with asynchronous, durable event processing | Accepted |
| ADR-005 | Deterministic policy-controlled autonomy with bounded actions, verification, audit, and rollback | Accepted |

Each ADR should document context, alternatives, decision, consequences, security implications, and validation criteria.

## 14. Immediate Execution Plan

Start with P0 and avoid implementing later-phase features prematurely.

Recommended sequence:
1. Define repository conventions, development workflow, and contribution standards.
2. Establish the initial architecture and security boundaries.
3. Define Gateway Connector protocol and integration capability contracts.
4. Define the versioned event schema and provenance requirements.
5. Implement the Integration Registry and initial OpenWrt connector.
6. Implement secure Node-to-gateway communication and manual configuration fallback.
7. Implement event ingestion, validation, normalization, and persistence.
8. Implement audit, health, logging, and metrics.
9. Add CI and tests for normal and failure scenarios.
10. Validate gateway independence when the Node is stopped.

### P0 Definition of Done

- Clean deployment from documented instructions.
- Gateway connection using the versioned connector protocol on a trusted local network.
- Capability discovery and manual fallback work.
- At least one real event is ingested and normalized.
- Event provenance is retained.
- Audit captures security-relevant configuration and connection events.
- Tests cover invalid input, residential source-provenance rejection, gateway disconnection, durable outbox persistence, retry-until-acknowledged, reconnection drain, and recovery after connector restart.
- Gateway forwarding is unaffected by Node availability.
- CI passes.

## 15. Open Questions to Resolve During P0

These questions should be resolved through implementation evidence rather than assumptions:

1. Which OpenWrt versions and hardware constraints will the first connector officially support?
2. Should the connector run directly on OpenWrt or on a nearby Linux host for the first supported setup?
3. Which authentication mechanism provides a practical, secure bootstrap and renewal flow for Node-to-gateway communication?
4. Which event envelope and identifiers are sufficient for correlation while minimizing sensitive data?
5. What is the minimum supported deployment resource profile for the Node?
6. Which initial two event sources provide the strongest end-to-end MVP demonstration?
7. What retention defaults balance useful investigation history with storage and privacy?

## 16. Success Principles

OpenShield is successful when a user can:
- Install the Node without replacing their existing network stack.
- Connect a supported gateway safely.
- Discover devices and supported integrations.
- Ingest and understand real events from multiple sources.
- See correlated incidents with evidence and risk context.
- Obtain useful local AI explanations without exporting sensitive data.
- Authorize a bounded response under deterministic policy.
- Verify, expire, or roll back that response where supported.
- Audit what happened and why.
- Keep the network operating safely when OpenShield Node is unavailable.

The first release should optimize for trust, safety, clarity, and a complete working vertical slice—not the number of integrations or the amount of automation.


## P0 implementation status — OpenWrt read-only integration

Current increment adds a read-only OpenWrt rpcd/ubus client used by the nearby-host Gateway Connector (not by the Node). OpenWrt's own RPC session login remains enabled; OpenShield API authentication is disabled in residential mode:

- Session login followed by `system.board` and `network.interface.dump`.
- Discovery returns normalized board identity and interface metadata.
- Health check verifies RPC reachability and returns basic device identity.
- HTTP timeout is bounded to 5 seconds; response bodies are capped at 1 MiB.
- TLS certificate verification uses Python's default HTTPS behavior.
- Credentials are supplied only to the connector through deployment environment variables, never integration configuration.
- Integration configuration rejects secret-like field names to prevent accidental API disclosure.
- The adapter advertises only `discover` and `health_check`; it does not claim event reading or enforcement.
- No firewall, routing, wireless, or forwarding mutation is implemented.

Environment:
- `OPENSHIELD_OPENWRT_URL`
- `OPENSHIELD_OPENWRT_USERNAME`
- `OPENSHIELD_OPENWRT_PASSWORD`
- Gateway integration ID defaults to `home-gateway` and is provisioned automatically by the Node on connector handshake.

Validation boundary:
- RPC behavior is covered with mocked transport tests.
- Real OpenWrt hardware/version compatibility is not yet validated.
- The nearby-host connector agent performs discovery at startup and forwards discovery/health envelopes to the Node without an OpenShield API key.
- P0 remains incomplete until a real normalized gateway event is verified on OpenWrt hardware, durable audit/recovery requirements are addressed, and gateway independence is validated.


## P0 implementation status — connector event forwarding

The nearby-host connector now uses the OpenWrt RPC client locally, keeping the Node out of the gateway management path:

- Optional connector configuration is all-or-nothing: OpenWrt URL, username, password, and registered integration ID.
- The gateway handshake advertises only `discover` and `health_check` when this adapter is configured; without it, no capabilities are advertised.
- After connection, the agent reads board/interface metadata and emits a `gateway.discovery` event.
- After each successful heartbeat, the agent emits a `gateway.health` event.
- RPC failures produce a bounded health event (`status=unavailable`, `reason=rpc_unavailable`) without forwarding exception text or credentials.
- Events use `openshield.event.v1`, include UTC timestamps and UUID event IDs, and preserve the configured integration ID as source provenance.
- The Node validates integration existence and kind. Residential mode trusts callers on the local network; source identity is provenance, not an authentication boundary.
- The connector remains outbound-only and does not modify forwarding, firewall, routing, or wireless configuration.

Required connector variables:
- `OPENSHIELD_OPENWRT_URL`
- `OPENSHIELD_OPENWRT_USERNAME`
- `OPENSHIELD_OPENWRT_PASSWORD`
- `OPENSHIELD_GATEWAY_ID` (default `home-gateway`)

The integration must be registered on the Node before event forwarding. Hardware validation is still pending.


## P0 implementation status — PostgreSQL persistence

PostgreSQL 16 is now the source of truth for the initial Node state:

- Integration registrations and capability/config metadata persist across Node restarts.
- Versioned events persist with their complete envelope and source provenance.
- Gateway connection records and heartbeat timestamps persist; the existing 90-second stale threshold is preserved.
- Duplicate integration IDs and event IDs are rejected.
- Schema creation is idempotent and performed automatically by the store.
- Node readiness checks PostgreSQL connectivity; no API-key configuration is required.
- Docker Compose provides PostgreSQL with a named data volume; stopping the stack does not remove this volume.
- The CI test service starts PostgreSQL and exercises persistence through a newly created store instance.

Configuration:
- `OPENSHIELD_POSTGRES_PASSWORD`
- `OPENSHIELD_DATABASE_URL`

Remaining:
- Durable audit records are not implemented yet.
- Formal versioned database migrations, backup/restore automation, pooling, and production hardening remain pending.
- Local tests must run through Docker Compose so the PostgreSQL dependency is available.


## P0 implementation status — durable audit trail

The PostgreSQL audit log now records security-relevant successful operations and gateway source authorization failures:

- `integration.registered`: actor, integration ID, kind, and declared capabilities.
- `gateway.connected`: actor/gateway ID, connector version, and accepted capabilities.
- `event.ingested`: actor, event ID, event type, severity, and source integration ID.
- `authorization.denied`: gateway source-ID mismatch attempts.
- State changes and their corresponding audit records are written in the same database transaction.
- Audit reads are exposed through `GET /api/v1/audit`, restricted to the admin role, with a bounded limit (1–500).
- Audit records contain no OpenWrt credentials. Residential API requests have no authenticated actor identity.

Remaining audit hardening:
- Authentication-failure auditing is deferred with authentication itself.
- Retention, export, tamper-evident chaining/signatures, and external immutable storage are pending.


## P0 implementation status — operational metrics

The Node now exposes an admin-protected Prometheus text endpoint at `GET /metrics`:

- HTTP request counters grouped by method, FastAPI route template, and status code.
- Event ingestion, gateway connection, gateway heartbeat, and gateway event-source denial counters.
- Labels avoid raw resource IDs and request values to limit cardinality.
- Metrics are process-local and thread-safe; no new runtime dependency was added.

Remaining:
- Counters reset on process restart.
- Histograms/latency, database gauges, scrape deployment, alerting, and long-term metrics storage remain pending.


## P0 implementation status — durable gateway event recovery

The nearby-host connector now uses a local SQLite outbox:

- Events are persisted before delivery and deleted only after the Node acknowledges them.
- The connector drains pending events in batches and retries after reconnect.
- When the Node is unavailable, the connector continues local OpenWrt discovery/health polling and queues resulting events.
- Node event ingestion is idempotent: duplicate event IDs return HTTP 202 with `status=duplicate`, so retries after a lost response are safe.
- Queue capacity is bounded at 10,000 pending events; the connector refuses new events when full rather than discarding older pending events.
- SQLite uses WAL and FULL synchronous mode. The database file is chmod 0600; the spool directory is enforced at mode 0700.
- Docker Compose mounts a named volume at `/var/lib/openshield`, preserving the spool across connector container restarts.

Configuration:
- `OPENSHIELD_GATEWAY_SPOOL_PATH` (default `/var/lib/openshield/gateway-spool.sqlite3`).

Remaining:
- Spool contents are not encrypted at rest; host/volume protection is required.
- Queue capacity/usage metrics and alerting are pending.
- A full hardware outage/recovery drill against a real OpenWrt router is pending.


## P0 hardware acceptance

CI validates mocked RPC transport, Node API behavior, database persistence, audit, metrics, and connector spool/retry behavior. It does not validate an actual OpenWrt firmware or prove forwarding independence on physical hardware.

Use [the OpenWrt P0 validation runbook](docs/operations/openwrt-validation.md) to verify:
- Actual rpcd authentication and read-only ACL compatibility.
- Real board/interface discovery and normalized event delivery.
- Continued LAN/DNS/Internet forwarding while the Node is stopped.
- Event spool growth during outage and delivery after Node recovery.
- Spool and gateway recovery after connector container restart.
- No firewall, routing, wireless, or forwarding changes.

P0 hardware acceptance remains pending until this runbook is executed on the target gateway and its evidence is recorded.


## P0 implementation checkpoint

**Software scope: implemented and CI-validated.** The current branch covers trusted-LAN residential API access, automatic gateway registration, gateway handshake and presence, OpenWrt read-only discovery/health, versioned event normalization, PostgreSQL state/audit persistence, metrics, and durable connector-side event retry/recovery.

**Physical gateway acceptance: pending.** Run the hardware validation runbook against the target OpenWrt model/firmware before marking P0 fully accepted. CI cannot establish real rpcd ACL compatibility or prove that the user's gateway continues forwarding during a Node outage.


## Residential deployment decision — current product stage

The first product stage targets a single household and a trusted local network. OpenShield API authentication, user accounts, API keys, and RBAC are intentionally disabled. The gateway connector defaults to `home-gateway`; its first handshake automatically provisions the corresponding OpenWrt integration. Heartbeats carry the gateway ID, and event provenance uses the same stable ID.

This is a deployment simplification, not a claim that unauthenticated APIs are safe on untrusted networks. The Node API must remain reachable only from the trusted home LAN and must not be exposed directly to the Internet. OpenWrt's own RPC authentication remains enabled to protect router management access.

Planned security evolution:
1. **Home:** trusted-LAN access, no OpenShield API credentials or user management.
2. **Business:** user/organization identity, gateway enrollment, roles, credential lifecycle, and stronger audit controls.
3. **SaaS:** tenant isolation, organization administration, quotas, billing, and managed control plane.

Business and SaaS authentication must be implemented and reviewed before those deployment profiles are enabled. Do not add dormant auth configuration requirements to the residential quick start.
