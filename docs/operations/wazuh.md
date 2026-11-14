# Wazuh Server API integration

OpenShield connects to the Wazuh **Server API** (normally HTTPS on port 55000). This is separate from the Wazuh Indexer API. Configure the Wazuh manager URL and a dedicated API account in the OpenShield dashboard.

## Permissions

Use a dedicated Wazuh API user assigned the built-in `readonly` role, or equivalent least-privilege policies. The integration reads agent records and manager information/status only. It does not enroll, restart, upgrade, delete, or otherwise modify agents, manager services, users, rules, or configuration.

The connector authenticates with:

- `POST /security/user/authenticate?raw=true` using HTTP Basic authentication. The JWT is held only in memory for the current diagnostics request.
- `GET /` for API metadata.
- `GET /manager/info` and `GET /manager/status` for manager version and daemon status.
- `GET /agents?limit=500&select=id,name,status,ip,version` for a bounded agent inventory.

Only the login endpoint uses POST. All other API operations are GET. Redirects are rejected, response bodies are limited to 1 MiB, and the client uses normal TLS certificate verification. Use a certificate trusted by the OpenShield Node; do not disable certificate verification for self-signed certificates.

## Credentials and diagnostics

The dashboard sends the base URL, username, and password to the Node. Username and password are encrypted at rest through `OPENSHIELD_SECRET_KEY` and are never returned in integration configuration or API responses. Removing credentials deletes the encrypted secret. Diagnostics are manually requested from the dashboard; no Wazuh service is installed, configured, or changed by OpenShield.

Agent inventory is capped at 500 records per diagnostics request to bound response size and processing time. The summary reports the total count returned by Wazuh and the number included in the response.
