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

The sync fetches page 1 only, with a maximum of 1,000 attributes per run. Supported MISP types are `ip-src`, `ip-dst`, `domain`, `hostname`, and `url`; only attributes with `to_ids=true` are retained. The response flags when the configured limit is reached, because more results may exist. Re-run with a MISP-side filtered dataset or a later pagination enhancement if the feed exceeds this bound.

Indicator upserts are idempotent by MISP source integration and attribute ID. Existing records not returned by a later sync are not automatically deleted or deactivated; review MISP deletion/expiration policy before relying on the local set as a complete mirror.

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

- Complete pagination and expiry/deletion reconciliation for large MISP feeds.
- Normalize CrowdSec decisions and MISP indicators into a common IOC model.
- Add explainable risk scoring and incident lifecycle/timelines with evidence provenance and false-positive handling.
- Evaluate source confidence, age, TLP/PAP markings and local overrides before risk aggregation.
