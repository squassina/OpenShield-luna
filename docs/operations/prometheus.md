# Prometheus read-only integration

OpenShield connects to the Prometheus HTTP API to read runtime metadata and active scrape-target health.

## Setup

1. Ensure the Prometheus HTTP API is reachable from the OpenShield Node.
2. If the endpoint requires authentication, configure a bearer token through the OpenShield dashboard. The token is encrypted at rest using `OPENSHIELD_SECRET_KEY`.
3. Register a Prometheus integration and load diagnostics.

The base URL must be an HTTP(S) origin without a path, query, fragment, or embedded credentials. Prefer HTTPS when the token crosses an untrusted network.

## Read-only scope

The adapter uses only:

- `GET /api/v1/status/runtimeinfo`
- `GET /api/v1/targets?state=active`

Responses are limited to 1 MiB. The diagnostics response includes runtime metadata and at most 100 active targets; the dashboard displays at most 25 target records. Unsupported paths and redirects are rejected.

OpenShield does not query PromQL, ingest or persist metric samples, create recording rules, or modify Prometheus configuration. Prometheus remains the source of truth for metrics.
