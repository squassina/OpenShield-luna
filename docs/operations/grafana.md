# Grafana read-only integration

OpenShield connects to the Grafana HTTP API to read instance health and dashboard metadata. It does not query metric or log data.

## Setup

1. Ensure the Grafana HTTP API is reachable from the OpenShield Node.
2. Create a dedicated service account with the minimum permissions needed to read instance health and dashboards. Create a token for that account.
3. Enter the Grafana origin and optional bearer token in the OpenShield dashboard. The token is encrypted at rest using `OPENSHIELD_SECRET_KEY`.

The base URL must be an HTTP(S) origin without a path, query, fragment, or embedded credentials. Prefer HTTPS when the token crosses an untrusted network. Grafana installations that allow unauthenticated read-only API access may omit the token.

## Read-only scope

The adapter uses only:

- `GET /api/health`
- `GET /api/search/?type=dash-db&limit=100`

The health response reports database status and Grafana version. Dashboard search is limited to 100 results. Responses are limited to 1 MiB; redirects and unsupported paths are rejected.

OpenShield does not create, update, or delete dashboards, folders, data sources, users, alerts, or service accounts. It does not query Prometheus or ingest metrics. Prometheus remains the metrics source of truth; Grafana is used only for health and dashboard metadata.

See the [Grafana HTTP API authentication documentation](https://grafana.com/docs/grafana/latest/developer-resources/api-reference/http-api/authentication/) for service account token setup and permissions.
