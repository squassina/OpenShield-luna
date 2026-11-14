# OpenShield — Technical Debt Register

This register separates known operational and product limitations from completed software. Issues are the source of truth for implementation and closure evidence.

## P0 — physical gateway validation

- [Issue #2 — Validate OpenWrt hardware, firmware, RPC ACLs, and forwarding independence](https://github.com/squassina/OpenShield/issues/2)
  - Validate the target router's real rpcd authentication and read-only ACL behavior.
  - Prove LAN, DNS, and Internet forwarding continue while the Node is unavailable.
  - Verify connector spool persistence, retry, recovery, and delivery after restart.

## P0 — OpenWrt device inventory and topology

**Software implementation:** MAC-keyed inventory and PostgreSQL first/last-seen persistence were introduced by PR [#26](https://github.com/squassina/OpenShield-luna/pull/26). PR [#28](https://github.com/squassina/OpenShield-luna/pull/28) was merged after CI passed; discovery now uses native LuCI ubus methods only.

**Current discovery path:**
- `system.board` and `network.interface dump` provide router/interface metadata.
- `luci-rpc.getHostHints` provides MAC-keyed IPv4/IPv6 host hints from LuCI's existing data sources.
- `luci-rpc.getDHCPLeases` enriches clients with DHCP hostname, addresses and logical interface where available.
- No custom router files, scripts, packages, ACL files, shell commands, SSH access, or `file.exec` permissions are used or required.
- PostgreSQL preserves first/last-seen data. The dashboard groups devices by DHCP logical interface and keeps unresolved devices under **Unmapped**.
- Connector discovery runs on its heartbeat interval (default 30 seconds); online/offline uses the current 90-second threshold.

**Remaining implementation/acceptance work:**
1. **Firmware compatibility:** on the Dynalink DL-WRX36, confirm the installed firmware exposes all four methods and determine which built-in ACL permissions authorize them. ACL group names vary by release; verify them on-device rather than assuming names from this runbook.
2. **Least privilege:** configure a dedicated rpcd account with only the required read permissions and verify authenticated remote calls. No custom ACL file or package should be installed.
3. **Inventory accuracy:** compare MAC, hostname, IPv4/IPv6 and logical-interface results against a known set of wired and wireless clients, including clients with static addresses and randomized MACs.
4. **Lifecycle:** verify IP changes retain MAC identity; verify disappearance, the 90-second offline transition, rediscovery, and persistence across connector restart.
5. **Resilience:** stop/restart the Node and connector; verify outbox recovery and confirm LAN, DNS and Internet forwarding remain operational throughout.
6. **Evidence:** record router model, firmware/rpcd versions, ACL permissions, test clients, observed inventory, event IDs, outage timings and results in the OpenWrt validation record.

**Known coverage limits / follow-up scope:**
- Host hints and DHCP leases reflect only data exposed by LuCI and the active DHCP backend. They do not guarantee visibility of every associated, static, sleeping or powered-on device.
- Logical interface is available only when lease metadata reports it; host-hint-only devices remain **Unmapped**.
- Wi-Fi association detail, bridge/VLAN membership, switch ports and physical Layer-2 links are not provided as a complete topology by this integration.
- MAC identity is scoped to one gateway. Cross-source identity reconciliation with Suricata/Zeek, randomized-MAC handling, spoofing detection, conflict handling and confidence scoring remain open.
- The 90-second online threshold is an initial heuristic and must be tuned against real router behavior.

The procedure is in [the OpenWrt validation runbook](operations/openwrt-validation.md), sections 10–11. Physical acceptance is tracked under [Issue #2](https://github.com/squassina/OpenShield/issues/2); broader identity enrichment and topology semantics are tracked under [Issues #5 and #8](https://github.com/squassina/OpenShield/issues/5).

## P1 — Network Visibility

- [Issue #4 — Validate Suricata and Zeek with live sensor deployments](https://github.com/squassina/OpenShield/issues/4)
  - P1 tests validate representative JSON records and the ingestion API. They do not prove live packet capture or end-to-end sensor deployment.
- [Issue #5 — Complete device identity enrichment across sources](https://github.com/squassina/OpenShield/issues/5)
  - Native LuCI host hints provide MAC identity and IPv4/IPv6 address hints; DHCP leases enrich hostname and logical-interface data where available. Remaining: richer Wi-Fi association and topology data, identity reconciliation across OpenWrt/Suricata/Zeek, conflict handling, and identity confidence.
- [Issue #6 — Event retention, pagination, and sustained-load validation](https://github.com/squassina/OpenShield/issues/6)
  - Event filters/limits and inventory/topology aggregation execute in PostgreSQL. Retention, cursor pagination, load benchmarks, and long-term storage strategy remain open.
- [Issue #7 — Authenticate sensor ingestion before Business deployment](https://github.com/squassina/OpenShield/issues/7)
  - Home mode intentionally trusts the LAN. Sensor ingestion has no per-sensor authentication or authorization; do not expose the Node API beyond the trusted LAN.
- [Issue #8 — Improve topology semantics beyond inferred IP connections](https://github.com/squassina/OpenShield/issues/8)
  - The dashboard includes a router-interface inventory grouped by logical OpenWrt interface. The flow graph describes observed IP connections; neither view is a complete Layer-2 map. VLAN membership, bridge ports, switch ports, Wi-Fi associations, routes, NAT relationships, and physical links remain unresolved.

## Deliberately deferred product scope

- Broader interactive event exploration and cross-source topology visualization remain P2; the OpenWrt logical-interface device inventory is implemented in the P0 gateway path.
- Privacy intelligence (Pi-hole/AdGuard), domain analytics, and privacy reports remain P2.
- None of these deferred features should be represented as implemented P1 functionality.

## P1 closure boundary

P1 software is considered complete when CI passes and documented API behavior is covered by automated tests. Live sensor deployment and physical gateway validation are tracked separately because they require a real target environment. Business/SaaS deployment remains blocked on the security work in Issue #7 and the broader authentication/authorization architecture.

## P2 — tracked follow-up issues

- [Issue #9 — High-volume DNS polling cursors and watermarks](https://github.com/squassina/OpenShield/issues/9): native Pi-hole v6/AdGuard Home polling and explicit, verified provider list synchronization are implemented. Polling currently reads the latest 500 records per invocation; durable cursors/watermarks remain open.
- [Issue #10 — Maintain DNS tracker and suspicious-domain classifications](https://github.com/squassina/OpenShield/issues/10): current suffix rules are intentionally small heuristics, not a maintained threat-intelligence feed.
- [Issue #13 — Complete service configuration lifecycle and security](https://github.com/squassina/OpenShield/issues/13): enable/disable, secure credential storage/rotation, service diagnostics, API/UI security, and guided connector configuration. Router-specific UI is tracked in #15.
- [Issue #14 — Automate DNS provider polling and dashboard refresh](https://github.com/squassina/OpenShield/issues/14): background polling, provider isolation, freshness/error state, manual sync, bounded pagination, and dashboard refresh.
- [Issue #15 — Configure OpenWrt router from the web interface](https://github.com/squassina/OpenShield/issues/15): guided router address/RPC credentials, connectivity and ACL validation, router discovery, connector status, and safe read-only setup. Depends on secure secret handling in #13; physical validation remains #2.

## Recently implemented on feature/technical-debt-2-4-6-13 (verify merge status)

- Event exploration has stable keyset cursor pagination using `received_at` and `event_id`.
- Integration records support enabled/disabled state; the dashboard exposes the toggle.
- Sensor event IDs are scoped by integration to prevent cross-sensor collisions; malformed non-object records are rejected.
- Gateway outbox restart persistence is explicitly covered by a test; physical forwarding independence remains a hardware acceptance task.
- Event retention has a bounded deletion primitive and an explicit CLI command. It is disabled by default; configure `OPENSHIELD_EVENT_RETENTION_DAYS` and run `python -m openshield.maintenance` in the backend environment.
