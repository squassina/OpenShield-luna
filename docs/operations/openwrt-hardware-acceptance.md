# OpenWrt physical acceptance — Phase 1A

Tracks [Issue #17](https://github.com/squassina/OpenShield-luna/issues/17). CI and mocked ubus tests do not prove compatibility with physical firmware.

## Safety boundary

- Target: Dynalink DL-WRX36 running the existing OpenWrt installation.
- Use only the existing LuCI /ubus API and built-in read-only RPC permissions.
- Do not install packages, scripts, custom ACL files, SSH helpers, or router-side agents.
- Do not change firewall, routing, wireless, VLAN, DNS, or forwarding configuration.
- Run Node-outage tests from a separate LAN client. Stop only the OpenShield Node container, never the router or gateway connector.
- Keep the Node API on the trusted LAN. Do not expose it to the Internet.
- Preserve Docker volumes; never use docker compose down -v.

## 1. Environment record

| Field | Value |
|---|---|
| Router model / board | |
| OpenWrt release / kernel | |
| rpcd / LuCI versions | |
| OpenShield Node image / commit | |
| Gateway Connector image / commit | |
| Test date / timezone | |
| LAN test client | |

Record exact ACL permissions granted to the dedicated RPC account. Confirm no write, UCI, shell, or file.exec permission.

## 2. RPC and discovery

1. Authenticate to the existing /ubus endpoint with the dedicated read-only account.
2. Verify system.board, network.interface dump, luci-rpc.getHostHints and luci-rpc.getDHCPLeases.
3. Configure the router through the OpenShield dashboard using that account.
4. Wait at least two connector heartbeats.
5. Inspect:
   - GET /api/v1/gateways
   - GET /api/v1/integrations
   - GET /api/v1/inventory/router-devices?limit=500
   - GET /api/v1/events?integration_id=home-gateway&limit=100
6. Compare discovered clients with a known wired/wireless client list, including DHCP, static-IP and randomized-MAC clients where available.
7. Record missed clients, duplicate identities, hostname/IP mismatches, interface mapping and IPv4/IPv6 coverage.

Expected: read-only discovery succeeds. DHCP interface metadata is preserved when available; host-hint-only clients may be Unmapped. MAC/IP is an observation, not cryptographic identity.

## 3. Presence and persistence

1. Record a test device's MAC, IP and last-seen timestamp.
2. Change its IP through normal network operations, if practical. Do not change router configuration solely for this test without approval.
3. Confirm the MAC-keyed record remains stable and the new address has provenance.
4. Disconnect one test client; verify offline transition after the current 90-second threshold.
5. Reconnect it and confirm online status.
6. Restart only the Gateway Connector; confirm inventory and first/last-seen history remain in PostgreSQL.

Do not force DHCP release on production clients.

## 4. Node outage and forwarding independence

Run during a maintenance window with a separate client continuously testing LAN reachability, DNS and Internet access.

Before the test, record baseline connectivity, gateway status, connector status and spool count (see openwrt-validation.md).

Stop only the Node:

~~~bash
docker compose stop openshield-node
~~~

During the outage verify:
- LAN traffic continues.
- DNS works according to the existing network configuration.
- Internet access remains available.
- Connector outbox count increases while events are produced and router RPC remains reachable.

Restore only the Node:

~~~bash
docker compose start openshield-node
~~~

Verify connector reconnection, queued event delivery, duplicate acknowledgement and outbox drain. Repeat with the Node stopped while restarting only the connector; confirm the SQLite spool survives process recreation.

Do not infer forwarding independence from a healthy container or mocked test. Record client-side observations throughout.

## 5. Results

| Check | Pass / Fail / N/A | Evidence |
|---|---|---|
| RPC authentication and read-only ACL | | |
| Board/interface discovery | | |
| Host hints / DHCP leases | | |
| IPv4 / IPv6 coverage | | |
| Identity / IP change | | |
| Offline / rediscovery | | |
| Connector restart persistence | | |
| Node outage: LAN / DNS / Internet | | |
| Outbox grows and drains | | |
| No router configuration changed | | |

Attach sanitized output and event IDs. Redact public IPs, hostnames, MACs, credentials, tokens and household identifiers.

## Acceptance

Close Issue #17 only after real-device evidence exists for every applicable check. CI is necessary but is not proof of physical forwarding continuity.
