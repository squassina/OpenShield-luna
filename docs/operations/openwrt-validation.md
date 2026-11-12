# OpenWrt P0 validation runbook

This runbook validates the first supported gateway path. CI uses mocked ubus/HTTP transports; **it does not prove compatibility with physical OpenWrt firmware**.

## 1. Prepare identities

Use one ID consistently:

- \`OPENSHIELD_GATEWAY_ID\`
- \`OPENSHIELD_INTEGRATION_ID\`
- Gateway API key record \`key_id\`
- Node integration \`integration_id\`

Register the integration in the Node using an admin key:

\`\`\`bash
curl -X POST http://localhost:8000/api/v1/integrations \
  -H "Authorization: Bearer $OPENSHIELD_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"integration_id":"openwrt-lab","kind":"openwrt","display_name":"OpenWrt lab gateway"}'
\`\`\`

The gateway API key must use \`key_id=openwrt-lab\` and role \`gateway\`. Store only its SHA-256 hash in \`OPENSHIELD_API_KEYS\`; give the raw key only to the connector.

## 2. Configure the connector

Set these variables in the deployment .env:

\`\`\`dotenv
OPENSHIELD_NODE_URL=http://openshield-node:8000
OPENSHIELD_GATEWAY_ID=openwrt-lab
OPENSHIELD_GATEWAY_API_KEY=<raw-gateway-api-key>
OPENSHIELD_OPENWRT_URL=https://<gateway-management-address>
OPENSHIELD_OPENWRT_USERNAME=<read-only-rpc-user>
OPENSHIELD_OPENWRT_PASSWORD=<rpc-password>
OPENSHIELD_INTEGRATION_ID=openwrt-lab
OPENSHIELD_GATEWAY_SPOOL_PATH=/var/lib/openshield/gateway-spool.sqlite3
\`\`\`

Use an OpenWrt RPC account with only the ubus permissions required for \`session.login\`, \`system.board\`, and \`network.interface.dump\`. Use HTTPS where supported. If management RPC is HTTP-only, isolate it on a trusted management network.

## 3. Start and verify

\`\`\`bash
docker compose up -d openshield-node
docker compose --profile gateway up -d openshield-gateway-connector
docker compose ps
\`\`\`

Verify gateway presence and event ingestion with admin credentials:

\`\`\`bash
curl http://localhost:8000/api/v1/gateways \
  -H "Authorization: Bearer $OPENSHIELD_ADMIN_API_KEY"

curl http://localhost:8000/api/v1/events \
  -H "Authorization: Bearer $OPENSHIELD_ADMIN_API_KEY"

curl "http://localhost:8000/api/v1/audit?limit=50" \
  -H "Authorization: Bearer $OPENSHIELD_ADMIN_API_KEY"
\`\`\`

Expected:
- Gateway status becomes \`connected\`.
- A \`gateway.discovery\` event contains board and interface metadata.
- \`gateway.health\` events arrive after heartbeats.
- Event source integration ID equals the gateway ID.
- Audit contains gateway connection and event ingestion records.
- No firewall, routing, wireless, or forwarding configuration is changed.

## 4. Verify Node outage behavior

First confirm normal client traffic through the gateway. Then stop only the Node:

\`\`\`bash
docker compose stop openshield-node
\`\`\`

Verify from a separate client that:
- LAN connectivity continues.
- DNS and Internet access continue according to the existing gateway configuration.
- The gateway does not depend on the Node for forwarding.

Inspect the connector outbox count:

\`\`\`bash
docker compose exec openshield-gateway-connector python -c "import os,sqlite3; p=os.environ.get('OPENSHIELD_GATEWAY_SPOOL_PATH','/var/lib/openshield/gateway-spool.sqlite3'); c=sqlite3.connect(p); print(c.execute('select count(*) from pending_events').fetchone()[0])"
\`\`\`

The count should increase while the Node is unavailable and OpenWrt RPC remains reachable.

Restart the Node:

\`\`\`bash
docker compose start openshield-node
\`\`\`

Wait for the connector to reconnect. Verify queued events appear in /api/v1/events and the spool count returns toward zero.

## 5. Verify connector restart recovery

With the Node available and pending events present, restart the connector:

\`\`\`bash
docker compose restart openshield-gateway-connector
\`\`\`

Verify:
- Gateway reconnects and heartbeat presence recovers.
- Pending events survive the connector container restart.
- Retries with the same event ID return \`duplicate\` and are acknowledged.
- The \`openshield-gateway-spool\` named volume remains present.

Do not use \`docker compose down -v\` during validation; it deletes persistent volumes.

## 6. Failure cases

Test one at a time:
- Wrong OpenWrt password: discovery/health must fail safely; no credential appears in logs or API output.
- Wrong gateway API key: Node rejects the connection; connector retains queued events.
- Mismatched gateway/integration ID: connector exits with a configuration error or Node rejects event source provenance.
- Node stopped during event delivery: event remains in the SQLite outbox and is retried.
- Spool full: new event is rejected and logged; older pending events are not deleted.

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
