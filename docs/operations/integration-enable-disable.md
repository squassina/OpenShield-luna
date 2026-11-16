# Integration enable/disable behavior

Disabling an integration is a strict ingestion boundary.

## When disabled

- Generic event ingestion returns HTTP 409.
- Sensor event ingestion returns HTTP 409.
- Direct DNS query ingestion returns HTTP 409.
- Manual DNS source sync returns HTTP 409.
- Background DNS polling skips the integration.
- New ingestion requests are not normalized or persisted.

Unknown integrations and integrations of the wrong provider kind retain their existing 404/400 responses. Authentication and source identity validation happen before the enabled-state check.

## Audit and retained data

Every rejected ingestion request writes an **integration.ingestion.rejected** audit record with the integration ID as target and only these details:

- source: events, sensor_events, dns_queries, or dns_manual_sync
- reason: integration_disabled

The rejected payload, DNS values, and credentials are not copied into the audit record. Events accepted before the integration was disabled remain stored; disabling does not delete history.

Requests queued by an external sender but delivered after disable are new ingestion attempts and are rejected. Re-enable the integration before retrying those requests.
