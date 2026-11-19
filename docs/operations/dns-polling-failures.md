# DNS polling failure isolation

DNS polling is isolated by integration for recoverable failures. One Pi-hole or AdGuard failure does not prevent later integrations from being polled in the same cycle.

## Failure categories

| Category | Boundary | Cursor behavior | Other integrations |
|---|---|---|---|
| `credential_error` | Stored credentials cannot be decrypted | Unchanged | Continue |
| `provider_error` | Provider request/authentication failure | Unchanged | Continue |
| `cursor_expired` | Provider pagination window expired | Unchanged; reset the source cursor explicitly | Continue |
| `normalization_error` | Provider page cannot be normalized as a whole | Unchanged | Continue |
| `unexpected_error` | Unexpected non-database exception for one integration | Unchanged | Continue |
| `database_error` | PostgreSQL persistence failure | Unchanged; abort the current cycle | Stop |

Malformed individual DNS records are handled separately: valid records are ingested, rejected records receive sanitized diagnostics, and the page is checkpointed only after all decisions are durable.

## Cursor and persistence guarantees

- Events are inserted idempotently before checkpointing.
- The provider cursor and page completion/rejection audit records are written in one PostgreSQL transaction.
- If event persistence or checkpointing fails, the cursor remains unchanged. Already inserted events are safely deduplicated when the page is retried.
- A PostgreSQL error aborts the cycle rather than attempting more integrations against an unavailable database.
- Recoverable provider, credential, normalization, and unexpected per-integration failures are recorded and polling continues with the next integration.

## Status and metrics

The privacy sources API includes **last_error_category**, **retryable**, and **last_rejected** alongside the last error and timestamps.

Prometheus counters use bounded labels only:

- `openshield_dns_poll_attempts_total{provider}`
- `openshield_dns_poll_success_total{provider}`
- `openshield_dns_poll_failures_total{provider,category}`
- `openshield_dns_poll_records_total{provider,outcome}`

The integration ID remains available in the privacy sources API and audit records, but is deliberately excluded from Prometheus labels to prevent one series per configured integration. `MetricsRegistry` accepts at most 4,096 distinct metric/label combinations by default. New series beyond the limit are dropped and counted by the fixed `openshield_metrics_series_dropped_total` metric; existing series continue to increment normally.

Failure messages and audit records contain category codes, not provider response bodies, credentials, or raw DNS record values.
