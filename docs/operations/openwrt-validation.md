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
OPENSHIELD_SECRET_KEY=<Fernet-key>
OPENSHIELD_SECRET_KEY_PREVIOUS=<old-key-during-rotation>
OPENSHIELD_GATEWAY_TOKEN=<random-connector-token>
OPENSHIELD_API_AUTH_ENABLED=true
OPENSHIELD_API_USERNAME=<admin-user>
OPENSHIELD_API_PASSWORD=<strong-admin-password>
OPENSHIELD_GATEWAY_SPOOL_PATH=/var/lib/openshield/gateway-spool.sqlite3
```

Generate a Fernet key with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. Generate a separate random connector token. Set the same `OPENSHIELD_GATEWAY_TOKEN` on Node and connector. Set `OPENSHIELD_SECRET_KEY` only on Node; back it up securely because losing it makes stored router credentials undecryptable. To rotate keys without downtime, set the new key as `OPENSHIELD_SECRET_KEY` and the old key in `OPENSHIELD_SECRET_KEY_PREVIOUS`; secrets are re-encrypted with the new key on read. After all secrets have been read/re-saved, remove the previous key. The dashboard stores credentials encrypted at rest; the authenticated connector receives them on connect/heartbeat. Do not set router credentials in the connector environment for normal operation. Use a dedicated OpenWrt RPC account with read-only access to `session.login`, `system.board`, `network.interface.dump`, `luci-rpc.getHostHints`, and `luci-rpc.getDHCPLeases`. Reuse the ACL groups already shipped with LuCI (`luci-base-network-status` and `luci-mod-status-realtime`, plus the system board read permission available on the installed release); do not create ACL files or install packages. Never grant `file.exec`, generic shell execution, or write permissions. Use HTTPS where supported. If management RPC is HTTP-only, isolate it on a trusted management network. API Basic authentication protects dashboard/admin routes; gateway traffic uses its separate bearer token.

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
- Wrong gateway token: connector handshake and event delivery must be rejected with HTTP 401.
- Wrong admin password: dashboard/API requests must be rejected; repeated failures are rate limited.
- Cross-origin state-changing browser request: must be rejected with HTTP 403.
- Node stopped during event delivery: event remains in the SQLite outbox and is retried.
- Spool full: new event is rejected and logged; older pending events are not deleted.
- Unknown event integration ID or mismatched source kind: Node rejects the event.

There is no OpenShield API-key rejection case in the residential profile. Source IDs preserve event provenance; they are not an authentication boundary.

## 7. Automated checks in CI

The gateway test suite covers outbox capacity, file permissions, process recreation, Node transport loss, retry, and acknowledgement. These tests validate connector persistence and delivery only. They do not verify packet forwarding on physical hardware.

## 8. Evidence to record

Record:
- OpenWrt model, firmware version, rpcd version.
- Connector image/tag and Node commit SHA.
- Successful connect/discovery/health event IDs.
- Node-stop start/end timestamps and client connectivity observations.
- Spool count before outage, during outage, and after recovery.
- Connector restart result.
- Any unexpected firewall/routing changes (expected: none).

P0 hardware acceptance requires these checks on the actual target gateway. CI passing alone is not hardware validation.


## 9. Configure OpenWrt from the dashboard

1. Open the **OpenWrt router** section.
2. Keep gateway ID `home-gateway` unless `OPENSHIELD_GATEWAY_ID` is configured differently on the connector.
3. Enter the management URL and a dedicated read-only rpcd account, then save.
4. The password is encrypted using `OPENSHIELD_SECRET_KEY`; it is never included in integration JSON or returned to the browser.
5. The connector retrieves the configuration using its separate `OPENSHIELD_GATEWAY_TOKEN` and applies it on the next connect/heartbeat.
6. The dashboard checks the latest gateway and router health event after saving. Status `connector_connected` means the connector is online but has not reported its next RPC check yet; `router_rpc_connected` confirms a successful RPC health check; `router_rpc_failed` means the connector is reachable but router RPC failed. Inspect discovery/health events for board and firmware details.

Set `OPENSHIELD_API_AUTH_ENABLED=true` only after configuring the admin username/password and gateway token on both Node and connector. When enabled, browser administration uses HTTP Basic authentication, state-changing cross-origin requests are rejected, and failed logins are rate limited. Health and metrics endpoints remain public for container orchestration/monitoring.


## 10. Device inventory using native LuCI ubus

The connector uses only the standard /ubus HTTP endpoint and methods exposed by the LuCI backend already present on a normal LuCI installation. No custom rpcd plugin, helper script, package, ACL file, SSH command, or shell execution is installed or required on the router.

Read-only calls used during discovery:
- system.board: router model, hostname, firmware and kernel metadata.
- network.interface dump: logical interface names, state, protocol and addresses.
- luci-rpc getHostHints: MAC-keyed host hints assembled by LuCI from the neighbor table, DHCP lease data, static host entries and known interface addresses. Includes IPv4 and IPv6 address hints when available.
- luci-rpc getDHCPLeases: DHCPv4/v6 lease details, including MAC, address, hostname and logical interface when supplied by the lease backend.

LuCI's host-hint method already reads the kernel neighbor table internally. OpenShield does not execute ip, read router files directly, or depend on a custom ubus object.

The dedicated RPC account needs read-only access to the corresponding existing LuCI ACL groups. On standard LuCI builds, luci-base-network-status covers host hints and interface status; luci-mod-status-realtime covers DHCP leases. The exact ACL group names and method availability must be confirmed against the installed firmware. Keep system.board read-only. Do not grant file.exec, broad file access, UCI writes, or any network/firewall write method.

After configuring the router in the dashboard, verify:
1. The next connector heartbeat succeeds and a new gateway.discovery event is ingested.
2. GET /api/v1/inventory/router-devices?limit=500 returns the gateway snapshot and MAC-keyed devices.
3. Devices with a DHCP lease are grouped under the lease's logical interface; devices known only through host hints appear under Unmapped.
4. IPv4 and IPv6 addresses are attached to the same MAC where LuCI reports them.
5. A device's MAC remains the identity when its IP address changes.
6. A device remains in inventory after disappearing from current host hints. Its state changes to offline when it has not been seen for more than 90 seconds.

Discovery boundaries: coverage depends on data exposed by the installed LuCI/rpcd-mod-luci and DHCP backend. Host hints can include neighbor and configured host data, but are not a guarantee that every associated or powered-on device is visible. DHCP lease data is limited to leases known to the router. Devices without a valid MAC cannot be merged into the MAC-keyed inventory. Logical interface is taken from DHCP lease metadata when available; host-hint-only devices remain Unmapped. This is not a physical Layer-2 map, switch-port map, or complete Wi-Fi association inventory.



## 11. Dashboard router setup

Open the Node dashboard on the trusted LAN and use OpenWrt router:
- Enter the stable Gateway ID used by the connector, router management URL, dedicated rpcd username and password.
- Save credentials. The Node encrypts them using OPENSHIELD_SECRET_KEY; the connector receives them only over the authenticated gateway channel. The password field is cleared after submission.
- The status panel reports connector presence, most recent RPC health check, board/firmware details and discovered interfaces. A successful check older than 90 seconds is shown as stale.
- Use Remove saved credentials to revoke the encrypted router credentials. The connector stops receiving the router configuration on its next heartbeat.

No router-side installation or configuration change is part of this workflow. Configure only the read-only permissions for the standard LuCI methods listed in section 10.

