# OpenWrt P0 validation runbook

This runbook validates the first supported gateway path. CI uses mocked ubus/HTTP transports; **it does not prove compatibility with physical OpenWrt firmware**.

## 1. Residential deployment boundary

The current residential profile has no OpenShield API authentication. Keep Node port 8000 reachable only from the trusted home LAN. Do not expose it to the Internet or configure public port forwarding.

The connector defaults to gateway ID `home-gateway`. Its first handshake automatically creates the corresponding OpenWrt integration in the Node; no manual registration or API key is required. You may set `OPENSHIELD_GATEWAY_ID` to another stable ID if needed.

## 2. Configure the connector

Set these variables in the deployment .env:

```dotenv
OPENSHIELD_NODE_URL=http://openshield-node:8000
OPENSHIELD_GATEWAY_ID=home-gateway
OPENSHIELD_OPENWRT_URL=https://<gateway-management-address>
OPENSHIELD_OPENWRT_USERNAME=<read-only-rpc-user>
OPENSHIELD_OPENWRT_PASSWORD=<rpc-password>
OPENSHIELD_GATEWAY_SPOOL_PATH=/var/lib/openshield/gateway-spool.sqlite3
```

OpenWrt URL, username, and password must be configured together. Use an OpenWrt RPC account with only the ubus permissions required for `session.login`, `system.board`, and `network.interface.dump`. Use HTTPS where supported. If management RPC is HTTP-only, isolate it on a trusted management network.

## 3. Start and verify

```bash
docker compose up -d openshield-node
docker compose --profile gateway up -d openshield-gateway-connector
docker compose ps
```

Verify gateway presence, automatic integration registration, events, and audit:

```bash
curl http://localhost:8000/api/v1/gateways
curl http://localhost:8000/api/v1/integrations
curl http://localhost:8000/api/v1/events
curl "http://localhost:8000/api/v1/audit?limit=50"
```

Expected:
- Gateway status becomes `connected`.
- An integration with ID `home-gateway` and kind `openwrt` is created automatically.
- A `gateway.discovery` event contains board and interface metadata.
- `gateway.health` events arrive after heartbeats.
- Event source integration ID equals the configured gateway ID.
- Audit contains gateway connection and event ingestion records.
- No firewall, routing, wireless, or forwarding configuration is changed.

## 4. Verify Node outage behavior

First confirm normal client traffic through the gateway. Then stop only the Node:

```bash
docker compose stop openshield-node
```

Verify from a separate client that:
- LAN connectivity continues.
- DNS and Internet access continue according to the existing gateway configuration.
- The gateway does not depend on the Node for forwarding.

Inspect the connector outbox count:

```bash
docker compose exec openshield-gateway-connector python -c "import os,sqlite3; p=os.environ.get('OPENSHIELD_GATEWAY_SPOOL_PATH','/var/lib/openshield/gateway-spool.sqlite3'); c=sqlite3.connect(p); print(c.execute('select count(*) from pending_events').fetchone()[0])"
```

The count should increase while the Node is unavailable and OpenWrt RPC remains reachable.

Restart the Node:

```bash
docker compose start openshield-node
```

Wait for the connector to reconnect. Verify queued events appear in `/api/v1/events` and the spool count returns toward zero.

## 5. Verify connector restart recovery and Node recovery

Keep the Node stopped from the previous step while restarting the connector. This avoids racing the connector's automatic queue drain:

```bash
docker compose restart openshield-gateway-connector
```

Before restarting the Node, inspect the spool count again using the command from the previous section. It must remain greater than zero after the connector restart.

Now restore the Node:

```bash
docker compose start openshield-node
```

Wait for the connector to reconnect. Verify:
- Gateway status and heartbeat presence recover.
- Previously queued events appear in `/api/v1/events`.
- The spool count returns to zero.
- Retries with an already-ingested event ID return `duplicate` and are acknowledged.
- The `openshield-gateway-spool` named volume remains present.

Do not use `docker compose down -v` during validation; it deletes persistent volumes.

## 6. Failure cases

Test one at a time:
- Wrong OpenWrt password: discovery/health must fail safely; no credential appears in logs or API output.
- Node stopped during event delivery: event remains in the SQLite outbox and is retried.
- Spool full: new event is rejected and logged; older pending events are not deleted.
- Unknown event integration ID or mismatched source kind: Node rejects the event.

There is no OpenShield API-key rejection case in the residential profile. Source IDs preserve event provenance; they are not an authentication boundary.

## 7. Evidence to record

Record:
- OpenWrt model, firmware version, rpcd version.
- Connector image/tag and Node commit SHA.
- Successful connect/discovery/health event IDs.
- Node-stop start/end timestamps and client connectivity observations.
- Spool count before outage, during outage, and after recovery.
- Connector restart result.
- Any unexpected firewall/routing changes (expected: none).

P0 hardware acceptance requires these checks on the actual target gateway. CI passing alone is not hardware validation.
