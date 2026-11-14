# Threat intelligence and incident workflow

OpenShield enriches existing network observations with CrowdSec CTI and MISP indicators. Enrichment is explicit and bounded; it does not automatically block traffic or change firewall/DNS policy.

## 1. Configure providers

In **Service integrations**, add one or more providers:

- **CrowdSec CTI:** create a CTI API key in the CrowdSec Console and enter it in the API key field. OpenShield uses the per-IP Enrichment API with the `x-api-key` header.
- **MISP:** enter the MISP base URL and an API key for a least-privilege user. OpenShield uses `POST /attributes/restSearch` with the API key in the `Authorization` header.

Provider keys are encrypted at rest using `OPENSHIELD_SECRET_KEY`; they are not returned by integration APIs or written into integration JSON. Back up the key and use the documented previous-key rotation procedure. Use HTTPS for provider connections.

CrowdSec CTI is an on-demand IP enrichment API, not a bulk feed. API quotas apply per key. MISP lookups support IP and domain indicators using MISP attribute search. References:
- CrowdSec Enrichment API: https://docs.crowdsec.net/u/cti_api/enrichment_api/
- CrowdSec API options and rate-limit model: https://docs.crowdsec.net/u/cti_api/api_introduction/
- MISP Automation API: https://www.misp.software/openapi/

The provider connection test performs one small lookup (CrowdSec uses `8.8.8.8`; MISP uses documentation IP `192.0.2.1`). CrowdSec test requests consume the provider quota.

## 2. Run enrichment

Use **Enrich recent events** in the dashboard, or call the API:

```bash
curl -X POST http://localhost:8000/api/v1/threat-intel/enrich \
  -H 'Content-Type: application/json' \
  --data '{"event_ids":["<event-id-1>","<event-id-2>"]}'
```

- Request size is limited to 100 event IDs.
- At most 50 unique indicators are queried per batch, prioritizing indicators observed in more events.
- Provider results are cached for six hours.
- CrowdSec is queried for public IP addresses only.
- MISP is queried for IP and normalized domain indicators.
- Provider failures are isolated and returned as sanitized per-integration errors. Raw API keys and arbitrary provider response fields are not persisted in incidents.

## 3. Risk score

Incidents are created only when CrowdSec reports a malicious/suspicious match (or a sufficiently high numeric score), or MISP returns an actionable attribute with `to_ids=true`.

The deterministic score is the sum of these bounded factors, capped at 100:

| Factor | Points |
|---|---:|
| Highest source-event severity | 0–40 |
| CrowdSec reputation | 10 known, 25 suspicious, 35 malicious |
| CrowdSec numeric score | 0–15 |
| MISP actionable attributes | 15–30 |
| MISP event threat level | 5–20 |
| Observation recency | 10 within 24h; 5 within 7d |

Risk bands: low (<35), medium (35–59), high (60–79), critical (80–100). These are triage priorities, not proof of compromise or authorization to block.

Every incident records the indicator, source events, provider, matched evidence, risk factors, first/last observation times, and current status. The incident detail API exposes an event timeline.

## 4. False-positive handling and audit

Incidents can be acknowledged, closed, or marked `false_positive`. A false-positive state is preserved during later enrichment; new evidence is still attached but does not silently reopen the incident. Status changes and incident creation/update are audited with actor-independent local audit records.

```bash
curl http://localhost:8000/api/v1/incidents?limit=50
curl http://localhost:8000/api/v1/incidents/<incident-id>
curl -X PATCH http://localhost:8000/api/v1/incidents/<incident-id> \
  -H 'Content-Type: application/json' \
  --data '{"status":"false_positive","reason":"Validated benign infrastructure"}'
```

P3 remains an intelligence and investigation layer. P5 owns deterministic policy authorization and response execution; P3 never modifies firewall, DNS, or gateway configuration.
