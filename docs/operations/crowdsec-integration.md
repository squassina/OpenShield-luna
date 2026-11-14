# CrowdSec Local API integration

OpenShield connects to the CrowdSec Local API (LAPI) over HTTP(S). The Node must be able to reach the configured LAPI address. Prefer HTTPS with a trusted certificate when the API is reached across hosts or networks.

## Credentials

1. Create a dedicated CrowdSec bouncer with `cscli bouncers add openshield` and copy its API key. OpenShield uses this key only with `GET /v1/decisions` through the `X-Api-Key` header.
2. Optionally provide an existing machine ID and password to read alert history. CrowdSec protects `GET /v1/alerts` with a watcher JWT, obtained through `POST /v1/watchers/login`. OpenShield keeps that JWT in memory for the request and uses it only with `GET /v1/alerts?limit=100`.
3. Enter the LAPI origin (for example `http://192.0.2.20:8080`), bouncer API key, and optional machine credentials in the OpenShield dashboard.

Machine credentials are optional: without them, OpenShield reads decisions only. Watcher credentials may grant broader Local API permissions than this integration needs; use a dedicated identity and understand its CrowdSec permissions before storing them. OpenShield does not call endpoints that create/delete alerts, create/delete decisions, register watchers, or change CrowdSec configuration.

All supplied credentials are encrypted at rest through `OPENSHIELD_SECRET_KEY`. They are never returned in integration configuration or dashboard responses. Removing credentials deletes the encrypted secret. Diagnostics are requested manually from the dashboard; no automatic polling or remote configuration is performed.

## Read-only data

- Decisions: `GET /v1/decisions` with the bouncer API key.
- Alerts: `GET /v1/alerts?limit=100` with the short-lived watcher JWT (optional).
- Login: `POST /v1/watchers/login` only when alert history is enabled.

See the [CrowdSec Local API specification](https://crowdsecurity.github.io/api_doc/index.html?urls.primaryName=LAPI) for endpoint security requirements and response schemas.
