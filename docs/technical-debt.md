# OpenShield — Technical Debt Register

This register separates known operational and product limitations from the completed P1 software scope. Issues are the source of truth for implementation and closure evidence.

## P0 — physical gateway validation

- [Issue #2 — Validate OpenWrt hardware, firmware, RPC ACLs, and forwarding independence](https://github.com/squassina/OpenShield/issues/2)
  - Validate the target router's real rpcd authentication and read-only ACL behavior.
  - Prove LAN, DNS, and Internet forwarding continue while the Node is unavailable.
  - Verify connector spool persistence, retry, recovery, and delivery after restart.

## P0 — OpenWrt device inventory and topology

**Implemented:** PR [#26](https://github.com/squassina/OpenShield-luna/pull/26) merged into `main` (merge commit `87c867b0b9e586f1c5d62ad33c09a59afd7ae61f`). The connector now collects IPv4 neighbors, resolves host hints and logical interfaces, and forwards a MAC-keyed inventory. PostgreSQL preserves first/last-seen data; the dashboard groups devices by logical interface and retains offline entries.

**Still required before calling the feature hardware-validated:**
- Install `scripts/openwrt/openshield-rpcd` and `scripts/openwrt/openshield-rpcd-acl.json` on the target router.
- Assign the least-privilege ACL to the dedicated rpcd account and verify the calls using that account (not only as root).
- Validate on the Dynalink DL-WRX36 and record exact OpenWrt/rpcd versions and ACL behavior.
- Confirm MAC/name/interface results against known wired and wireless clients, including a client whose IPv4 address changes.
- Verify online-to-offline transition, persistence after disappearance, connector restart, and Node outage/recovery.
- Confirm the helper does not alter firewall, routing, wireless, or forwarding state.

**Known coverage limits (follow-up work):**
- Discovery currently uses IPv4 neighbor entries. IPv6 NDP is not collected.
- Devices with no current neighbor entry are not newly discovered. Sleeping clients may appear offline even when powered on.
- Hostnames depend on `luci-rpc getHostHints`; a missing hint is shown as `(sem-nome)`.
- Wi-Fi association tables, full DHCP lease data, bridge/VLAN membership, switch ports, and physical Layer-2 links are not collected.
- MAC identity is scoped to a gateway. Cross-source identity reconciliation, randomized-MAC handling, spoofing detection, and confidence scoring are not implemented.
- The 90-second online threshold is a fixed initial heuristic; tune it against real heartbeat/neighbor behavior after hardware validation.

The detailed installation and acceptance procedure is in [the OpenWrt validation runbook](operations/openwrt-validation.md), section 10. The physical validation is tracked under [Issue #2](https://github.com/squassina/OpenShield/issues/2), and broader identity/topology work under [Issues #5 and #8](https://github.com/squassina/OpenShield/issues/5).

## P1 — Network Visibility

- [Issue #4 — Validate Suricata and Zeek with live sensor deployments](https://github.com/squassina/OpenShield/issues/4)
  - P1 tests validate representative JSON records and the ingestion API. They do not prove live packet capture or end-to-end sensor deployment.
- [Issue #5 — Complete device identity enrichment across sources](https://github.com/squassina/OpenShield/issues/5)
  - Native LuCI host hints now provide MAC identity and IPv4/IPv6 address hints; DHCP leases enrich hostname and logical-interface data where available. Remaining: richer Wi-Fi association and topology data, identity reconciliation across OpenWrt/Suricata/Zeek, conflict handling, and identity confidence.
- [Issue #6 — Event retention, pagination, and sustained-load validation](https://github.com/squassina/OpenShield/issues/6)
  - Event filters/limits and inventory/topology aggregation now execute in PostgreSQL. Retention, cursor pagination, load benchmarks, and long-term storage strategy remain open.
- [Issue #7 — Authenticate sensor ingestion before Business deployment](https://github.com/squassina/OpenShield/issues/7)
  - Home mode intentionally trusts the LAN. Sensor ingestion has no per-sensor authentication or authorization; do not expose the Node API beyond the trusted LAN.
- [Issue #8 — Improve topology semantics beyond inferred IP connections](https://github.com/squassina/OpenShield/issues/8)
  - The dashboard now includes a router-interface inventory grouped by logical OpenWrt interface. The flow graph still describes observed IP connections; neither view is a complete Layer-2 map. VLAN membership, bridge ports, switch ports, Wi-Fi associations, routes, NAT relationships, and physical links remain unresolved.

## Deliberately deferred product scope

- Broader interactive event exploration and cross-source topology visualization remain P2; the OpenWrt logical-interface device inventory is implemented in the P0 gateway path.
- Privacy intelligence (Pi-hole/AdGuard), domain analytics, and privacy reports remain P2.
- None of these deferred features should be represented as implemented P1 functionality.

## P1 closure boundary

P1 software is considered complete when CI passes and the documented API behavior is covered by automated tests. Live sensor deployment and physical gateway validation are tracked separately because they require a real target environment. Business/SaaS deployment remains blocked on the security work in Issue #7 and the broader authentication/authorization architecture.


## P2 — tracked follow-up issues

- [Issue #9 — High-volume DNS polling cursors and watermarks](https://github.com/squassina/OpenShield/issues/9): native Pi-hole v6/AdGuard Home polling and explicit, verified provider list synchronization are implemented. Polling currently reads the latest 500 records per invocation; durable cursors/watermarks remain open.
- [Issue #10 — Maintain DNS tracker and suspicious-domain classifications](https://github.com/squassina/OpenShield/issues/10): current suffix rules are intentionally small heuristics, not a maintained threat-intelligence feed.

- [Issue #13 — Complete service configuration lifecycle and security](https://github.com/squassina/OpenShield/issues/13): enable/disable, secure credential storage/rotation, service diagnostics, API/UI security, and guided connector configuration. Router-specific UI is tracked in #15.
- [Issue #14 — Automate DNS provider polling and dashboard refresh](https://github.com/squassina/OpenShield/issues/14): background polling, provider isolation, freshness/error state, manual sync, bounded pagination, and dashboard refresh.
- [Issue #15 — Configure OpenWrt router from the web interface](https://github.com/squassina/OpenShield/issues/15): guided router address/RPC credentials, connectivity and ACL validation, router discovery, connector status, and safe read-only setup. Depends on secure secret handling in #13; physical validation remains #2.


## Recently implemented on feature/technical-debt-2-4-6-13 (pending CI/merge)
- Event exploration now has stable keyset cursor pagination using received_at and event_id.
- Integration records support enabled/disabled state; the dashboard exposes the toggle.
- Sensor event IDs are scoped by integration to prevent cross-sensor collisions; malformed non-object records are rejected.
- Gateway outbox restart persistence is explicitly covered by a test; physical forwarding independence remains a hardware acceptance task.
- Event retention has a bounded deletion primitive and an explicit CLI command. It is disabled by default; configure OPENSHIELD_EVENT_RETENTION_DAYS and run python -m openshield.maintenance in the backend environment.
