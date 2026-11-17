# Suricata and Zeek sensor forwarding

OpenShield accepts bounded JSON batches from Suricata EVE and Zeek JSON logs. Register a sensor first in **Service integrations**; choose kind `suricata` or `zeek`, then copy the resulting integration ID. Issue a token once per integration with the credential endpoint (requires administrator authentication when enabled):\n\n```bash\nexport SENSOR_TOKEN="$(curl --fail-with-body -sS -X PUT \\\n  http://openshield-node:8000/api/v1/sensors/suricata-home/credentials | jq -r .token)"\n```\n\nStore this token in the sensor shipper's secret store. The plaintext is returned only during creation/rotation; rotate it to invalidate the previous token, or DELETE the same endpoint to revoke it.

## 1. Suricata

Enable EVE JSON output in `suricata.yaml`:

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - flow
        - dns
        - http
        - tls
        - ssh
        - anomaly
```

Restart Suricata and confirm it writes JSON lines to `eve.json`. Smoke-test ingestion with a representative event (replace the integration ID and Node URL):

```bash
curl --fail-with-body -X POST \
  http://openshield-node:8000/api/v1/sensors/suricata-home/events \
  -H 'Content-Type: application/json' \
  --data-binary '[
    {
      "timestamp": "2026-11-13T12:00:00.000000+0000",
      "event_type": "alert",
      "src_ip": "192.168.1.20",
      "src_port": 51514,
      "dest_ip": "203.0.113.10",
      "dest_port": 443,
      "proto": "TCP",
      "alert": {
        "signature": "Example test alert",
        "category": "Test",
        "severity": 2,
        "signature_id": 9900001
      }
    }
  ]'
```

## 2. Zeek

Enable JSON logs in the Zeek deployment (for example in `local.zeek`):

```zeek
@load policy/tuning/json-logs
redef LogAscii::use_json = T;
```

Ensure the `conn.log`, `dns.log`, `http.log`, and `ssl.log` files are emitted as JSON lines. Smoke-test ingestion:

```bash
curl --fail-with-body -X POST \
  http://openshield-node:8000/api/v1/sensors/zeek-home/events \
  -H 'Content-Type: application/json' \
  --data-binary '[
    {
      "_path": "conn",
      "ts": 1794571200.0,
      "uid": "C-test-001",
      "id.orig_h": "192.168.1.20",
      "id.orig_p": 51514,
      "id.resp_h": "203.0.113.10",
      "id.resp_p": 443,
      "proto": "tcp",
      "service": "ssl",
      "conn_state": "SF"
    }
  ]'
```

## 3. Batch and security requirements

- Send a JSON array of 1–500 records per request; keep the request body below 5 MiB.
- Preserve the original sensor timestamps. OpenShield assigns its own observation timestamp.
- Retries are safe for duplicate event IDs; include Suricata `community_id` or Zeek `uid` when available.
- The Node normalizers retain only allowlisted fields; arbitrary sensor fields are discarded.
- Send the integration-scoped bearer token in the `Authorization` header; tokens cannot be reused across integrations.\n- Default application limits: 120 ingestion requests per client IP per 60 seconds, 10 sensor credential operations per client IP per 60 seconds, and 5 MiB per request. A 429 response includes `Retry-After`.\n- Keep Node reachable only from the trusted sensor network. Compose binds to loopback by default; when enabling LAN access, bind to the Node's specific LAN IP and restrict port 8000 with the host firewall. Use a TLS reverse proxy for untrusted network segments and apply additional edge rate limits.
- Do not send PCAPs, raw packet payloads, passwords, or unrelated local files to these endpoints.

## 4. Verify

```bash
curl http://openshield-node:8000/api/v1/sensors
curl 'http://openshield-node:8000/api/v1/events?integration_id=suricata-home&limit=20'
```

The sensor status is based on the most recent event observed by Node; it is not proof that every upstream log line was forwarded. Deploy a persistent log shipper with checkpointed offsets for production use, and monitor its own backlog/retry metrics.
