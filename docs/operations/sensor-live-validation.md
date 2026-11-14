# Live Suricata and Zeek acceptance — Phase 1B

Tracks [Issue #18](https://github.com/squassina/OpenShield-luna/issues/18). Unit tests validate normalizers and API behavior; they do not validate packet capture, real versions, log rotation, shipper offsets or sustained delivery.

## Safety and deployment boundary

- Deploy sensors on an authorized capture host or mirror/SPAN interface.
- Do not install or configure sensors on the OpenWrt router as part of this procedure.
- Do not enable inline IPS, blocking, firewall changes or packet injection.
- Do not send PCAPs or raw payloads to OpenShield. Forward supported JSON fields only.
- Keep sensor ingestion reachable only from the trusted sensor network. Per-sensor authentication remains tracked by Issue #7.
- Use a dedicated integration ID per sensor.

## 1. Environment record

| Field | Suricata | Zeek |
|---|---|---|
| Version | | |
| OS / kernel | | |
| Capture interface / mirror | | |
| Capture mode | | |
| JSON log path | | |
| Shipper and version | | |
| OpenShield image / commit | | |
| Integration ID | | |
| Test date / timezone | | |

Record interface speed, packet drops, CPU, memory and disk baseline. Do not include sensitive packet payloads or secrets.

## 2. Supported JSON streams

Follow [sensor-exporters.md](sensor-exporters.md) for baseline EVE JSON and Zeek JSON settings. Validate at least:

- Suricata EVE: alert, flow, DNS, HTTP and TLS.
- Zeek JSON: conn, dns, http and ssl.
- Original sensor timestamps remain distinct from Node observation time.
- Stable IDs are present where available (community_id for Suricata, uid for Zeek).
- Shipper uses persistent/checkpointed offsets and bounded retries.
- Log rotation does not skip or resend unbounded ranges.

A successful curl smoke test does not prove the log shipper works.

## 3. End-to-end test matrix

Run separately for each sensor. Retain sanitized evidence.

| Test | Procedure | Expected |
|---|---|---|
| Initial delivery | Generate authorized test traffic | Event visible under correct integration |
| Supported types | Produce alert/flow/DNS/HTTP/TLS or conn/DNS/HTTP/SSL | Supported types normalize |
| Duplicate retry | Replay same record / retry after lost acknowledgement | First accepted; replay duplicate |
| Node outage | Stop Node during controlled window; shipper remains running | Shipper backlog grows; offsets do not silently advance |
| Node recovery | Restart Node and allow retries | Backlog drains; events visible |
| Sensor restart | Restart sensor and shipper independently | Delivery resumes |
| Log rotation | Rotate JSON log normally | No missing range; duplicates bounded |
| Malformed record | Send malformed JSON in a test fixture | Error visible; later valid records continue |
| Oversized input | Send >500 records or body >5 MiB | Predictable rejection; no partial silent acceptance |
| Freshness | Stop event generation for >5 minutes | Health transitions healthy to stale |
| Resource use | Observe drops, CPU, memory and disk | Measurements recorded; no unbounded growth |

The API accepts 1–500 records per request and rejects bodies above 5 MiB. Sensor health uses Node-observed event time and a five-minute freshness window; it does not prove every upstream line was forwarded.

## 4. API verification

After registering each sensor in Service integrations:

~~~bash
curl --fail-with-body http://openshield-node:8000/api/v1/sensors
curl --fail-with-body 'http://openshield-node:8000/api/v1/events?integration_id=<integration-id>&limit=100'
~~~

Confirm event type, source integration, timestamp, severity and normalized fields. Confirm arbitrary fields and secrets are not retained. Compare shipper source offsets/backlog with accepted event counts.

## 5. Results and acceptance

| Evidence | Suricata | Zeek |
|---|---|---|
| Version and deployment config | | |
| Initial events visible | | |
| Supported record types | | |
| Duplicate retry | | |
| Node outage / recovery | | |
| Sensor restart | | |
| Log rotation | | |
| Malformed / oversized input | | |
| Freshness transition | | |
| Sustained throughput / drops | | |

Attach sanitized EVE/Zeek fixtures only where privacy and licensing permit, API response summaries, shipper backlog metrics and resource measurements. Redact identifying IPs.

Close Issue #18 only after both streams are validated on real deployments with repeatable evidence. Mock tests and manually posted curl records are not live sensor acceptance.
