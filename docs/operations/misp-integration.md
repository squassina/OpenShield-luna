# MISP threat-intelligence integration

This increment adds a read-only MISP connector and exact IOC matching against stored network events. It does not block traffic, change MISP data, or treat an IOC match as proof of compromise.

## Setup

Register a MISP integration:

~~~bash
curl -X POST http://localhost:8000/api/v1/integrations \
  -H 'Content-Type: application/json' \
  -d '{"integration_id":"misp-home","kind":"misp","display_name":"MISP"}'
~~~

Store the API key encrypted using the Node's configured `OPENSHIELD_SECRET_KEY`:

~~~bash
curl -X PUT http://localhost:8000/api/v1/integrations/misp-home/misp-credentials \
  -H 'Content-Type: application/json' \
  -d '{"base_url":"https://misp.example","api_key":"<MISP_API_KEY>"}'
~~~

The key must belong to a MISP account with read-only access to the required API endpoints. Use HTTPS and a least-privilege account. Never put the key in integration config, logs, source control, or shell history.

## Diagnostics and synchronization

~~~bash
curl http://localhost:8000/api/v1/integrations/misp-home/misp-diagnostics
curl -X POST 'http://localhost:8000/api/v1/integrations/misp-home/misp-sync?limit=1000'
curl 'http://localhost:8000/api/v1/threat-intel/indicators?limit=200'
curl 'http://localhost:8000/api/v1/threat-intel/matches?event_limit=500&indicator_limit=1000'
~~~

The sync follows MISP pagination using bounded pages of at most 250 attributes and a total cap of 1,000 indicators per run. Only `to_ids=true` attributes of supported types (`ip-src`, `ip-dst`, `domain`, `hostname`, and `url`) are retained. Duplicate attribute IDs across pages are collapsed. The API response flags when the total cap is reached because more results may exist; increase the cap only through a reviewed configuration change.

Indicator upserts are idempotent by MISP source integration and attribute ID. Reconciliation removes stored indicators absent from a successfully fetched snapshot only when the result count is below the requested limit, which proves pagination ended before reaching the cap. A result at the cap is treated as potentially truncated: it is upserted, but no existing indicators are removed. Failed requests also leave the previous inventory untouched. This reconciles the supported, currently returned IDS-enabled attributes; MISP-side deletion and expiration semantics remain dependent on what the configured MISP search endpoint returns.

## Matching semantics

The matches endpoint compares exact IP addresses and exact domain/hostname values against recent stored events. URL indicators are retained for visibility but are not matched in this increment. Domain suffix matching, URL path matching, CIDR expansion, fuzzy matching, reputation scoring, and incident aggregation are not implemented here.

Each result carries the MISP attribute and event provenance. A match is a lead for investigation, not a verdict. No response action is available from this integration.

## Security and boundaries

- MISP API key is stored in the encrypted integration secret store and never returned by the API.
- The client accepts only HTTPS or HTTP origins without URL credentials, paths, query strings, or fragments.
- Redirects are disabled; requests have bounded timeouts and a 5 MiB response limit.
- Only the version and attribute search endpoints are allowed.
- The adapter is read-only; no event, attribute, or feed mutation is performed.
- Keep OpenShield on the trusted LAN. Residential API authentication remains governed by the existing deployment profile.

## Follow-up P3 work

- Reconcile MISP deletion/expiration state after complete, successful pagination.
- Normalize CrowdSec decisions and MISP indicators into a common IOC model.
- Add explainable risk scoring and incident lifecycle/timelines with evidence provenance and false-positive handling.
- Evaluate source confidence, age, TLP/PAP markings and local overrides before risk aggregation.
