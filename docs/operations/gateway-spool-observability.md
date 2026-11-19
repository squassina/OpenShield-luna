# Gateway spool observability

The nearby-host Gateway Connector reports a snapshot of its durable SQLite outbox counters with each v1 heartbeat. The Node validates the payload and exports metrics at `GET /metrics`.

## Metrics

All series are labelled by `gateway_id` only. The registry-wide 4,096-series limit applies to these and all other metrics; attempts to add a new series after the cap are counted by `openshield_metrics_samples_dropped_total`.

| Metric | Type | Meaning |
|---|---|---|
| `openshield_gateway_spool_pending_events` | Gauge | Current number of queued events |
| `openshield_gateway_spool_capacity` | Gauge | Configured maximum queue depth |
| `openshield_gateway_spool_evicted_events_total` | Counter snapshot | Cumulative low-priority events evicted to make room |
| `openshield_gateway_spool_coalesced_health_events_total` | Counter snapshot | Cumulative identical health snapshots compacted |
| `openshield_gateway_spool_dropped_events_total` | Counter snapshot | Cumulative incoming events rejected because protected events filled the queue |
| `openshield_gateway_spool_last_report_timestamp_seconds` | Gauge | Unix timestamp of the latest accepted spool snapshot |

The three `*_total` values come from durable SQLite counters. They are set from the connector snapshot on each heartbeat rather than incremented at the Node, so a connector restart does not lose their history. If the spool database is intentionally recreated, its counters restart at zero; Prometheus treats a decrease in a counter as a reset.

The `last_report_timestamp_seconds` gauge makes missing telemetry visible separately from a zero-length queue. The regular gateway heartbeat still updates connection presence; older v1 connectors that omit the optional `spool_stats` payload remain compatible.

## Example Prometheus alert rules

Tune thresholds and durations to the deployment's heartbeat interval and capacity:

```yaml
groups:
  - name: openshield-gateway-spool
    rules:
      - alert: OpenShieldGatewaySpoolHighWatermark
        expr: |
          openshield_gateway_spool_pending_events
          / on (gateway_id) openshield_gateway_spool_capacity > 0.80
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Gateway {{ $labels.gateway_id }} spool is above 80% capacity"

      - alert: OpenShieldGatewaySpoolDroppedEvents
        expr: increase(openshield_gateway_spool_dropped_events_total[5m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Gateway {{ $labels.gateway_id }} rejected events because its spool was full"

      - alert: OpenShieldGatewaySpoolEvictions
        expr: increase(openshield_gateway_spool_evicted_events_total[5m]) > 0
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "Gateway {{ $labels.gateway_id }} evicted queued events"

      - alert: OpenShieldGatewaySpoolTelemetryStale
        expr: time() - openshield_gateway_spool_last_report_timestamp_seconds > 90
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "Gateway {{ $labels.gateway_id }} has not reported spool telemetry recently"
```

The stale threshold must exceed the configured heartbeat interval plus expected network delay. A newly connected gateway does not publish spool metrics until its first heartbeat with statistics.

## Trust and operational boundary

- Telemetry contains only bounded integer counters and queue capacity; it does not include event payloads, IP addresses, hostnames, MAC addresses, credentials, or router configuration.
- The heartbeat endpoint validates non-negative counters, a positive capacity, and `pending_events <= capacity`. Unknown fields and malformed values are rejected.
- Values are connector-reported and useful for operational monitoring only. They are never used to authorize commands, alter policy, or enforce network controls.
- Metrics are process-local to the Node and reset on Node restart. The next connector heartbeat repopulates the latest snapshot from the durable SQLite spool.
- The connector spool itself remains unencrypted at rest; protect the host and Docker volume as documented in the gateway connector section of the README.
