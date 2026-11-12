# OpenShield — Technical Debt Register

This register separates known operational and product limitations from the completed P1 software scope. Issues are the source of truth for implementation and closure evidence.

## P0 — physical gateway validation

- [Issue #2 — Validate OpenWrt hardware, firmware, RPC ACLs, and forwarding independence](https://github.com/squassina/OpenShield/issues/2)
  - Validate the target router's real rpcd authentication and read-only ACL behavior.
  - Prove LAN, DNS, and Internet forwarding continue while the Node is unavailable.
  - Verify connector spool persistence, retry, recovery, and delivery after restart.

## P1 — Network Visibility

- [Issue #4 — Validate Suricata and Zeek with live sensor deployments](https://github.com/squassina/OpenShield/issues/4)
  - P1 tests validate representative JSON records and the ingestion API. They do not prove live packet capture or end-to-end sensor deployment.
- [Issue #5 — Enrich observed IP inventory with device identity](https://github.com/squassina/OpenShield/issues/5)
  - Current inventory is an observed IP endpoint list. MAC, hostname, DHCP lease, ARP/NDP, VLAN, and identity confidence are not yet integrated.
- [Issue #6 — Event retention, pagination, and sustained-load validation](https://github.com/squassina/OpenShield/issues/6)
  - Event filters/limits and inventory/topology aggregation now execute in PostgreSQL. Retention, cursor pagination, load benchmarks, and long-term storage strategy remain open.
- [Issue #7 — Authenticate sensor ingestion before Business deployment](https://github.com/squassina/OpenShield/issues/7)
  - Home mode intentionally trusts the LAN. Sensor ingestion has no per-sensor authentication or authorization; do not expose the Node API beyond the trusted LAN.
- [Issue #8 — Improve topology semantics beyond inferred IP connections](https://github.com/squassina/OpenShield/issues/8)
  - Current graph describes observed IP flows and inferred private/public direction. It is not a Layer-2 map and does not resolve VLANs, routes, NAT, or physical links.

## Deliberately deferred product scope

- Interactive web dashboard and visual topology exploration remain P2.
- Privacy intelligence (Pi-hole/AdGuard), domain analytics, and privacy reports remain P2.
- None of these deferred features should be represented as implemented P1 functionality.

## P1 closure boundary

P1 software is considered complete when CI passes and the documented API behavior is covered by automated tests. Live sensor deployment and physical gateway validation are tracked separately because they require a real target environment. Business/SaaS deployment remains blocked on the security work in Issue #7 and the broader authentication/authorization architecture.


## P2 — tracked follow-up issues

- [Issue #9 — High-volume DNS polling cursors and watermarks](https://github.com/squassina/OpenShield/issues/9): native Pi-hole v6/AdGuard Home polling and explicit, verified provider list synchronization are implemented. Polling currently reads the latest 500 records per invocation; durable cursors/watermarks remain open.
- [Issue #10 — Maintain DNS tracker and suspicious-domain classifications](https://github.com/squassina/OpenShield/issues/10): current suffix rules are intentionally small heuristics, not a maintained threat-intelligence feed.
