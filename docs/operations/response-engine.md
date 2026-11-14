# P5 — Deterministic response engine

## Supported actions

P5 separates deterministic policy evaluation from execution. Two allowlisted actions are supported:

- `dns_block_domain`: block a domain through one configured Pi-hole v6 or AdGuard Home integration.
- `firewall_block_ip`: block a public IPv4 address through the authenticated OpenWrt connector and the dedicated nftables RPC plugin.

Policies define a minimum incident risk score, provider/gateway, action, TTL (60 seconds to 7 days), and approval requirement. No policy is created by default. Only domain indicators match DNS policies; only globally routable IPv4 indicators match firewall policies. IPv6 and arbitrary commands are not supported.

## Safety behavior

- Incidents marked closed or false positive are not actionable.
- Risk score >= 80 always requires human approval. Firewall actions always require human approval, regardless of policy setting.
- AI investigation output is never used as authorization or executable instructions.
- The global kill switch blocks new execution, cancels pending approvals/queued actions, and requests rollback for active actions. In-flight gateway results are reconciled; an action applied during the stop is immediately queued for rollback.
- DNS blocks are written to the OpenShield-managed local list, synchronized to one selected provider, and verified by the provider adapter.
- OpenWrt firewall blocks use only the custom `openshield-firewall.block_ip/unblock_ip` rpcd object. The connector cannot run arbitrary shell commands or modify general UCI firewall configuration.
- Firewall blocks are applied to the dedicated `inet fw4` set and carry an nftables element timeout. The timeout remains effective if the Node or connector is unavailable.
- Gateway callbacks must report the expected IP and operation result; the Node validates this evidence before marking an action active or rolled back.
- DNS synchronization failure triggers local compensation. If compensation/rollback fails, the action enters `rollback_pending` and retries with bounded exponential backoff.
- Each action has a unique ownership marker. Rollback removes only the entry owned by that action; pre-existing/manual blocks are not removed.
- Policy, action, approval, rejection, rollback and kill-switch transitions are audited.

## OpenWrt firewall plugin installation

The firewall action requires OpenWrt firewall4/nftables and the dedicated rpcd executable plugin shipped in `scripts/openwrt/`. Install the three files on the router:

```sh
install -D -m 0755 openshield-firewall /usr/libexec/rpcd/openshield-firewall
install -D -m 0644 openshield.nft /etc/nftables.d/openshield.nft
install -D -m 0644 openshield-rpcd-acl.json /usr/share/rpcd/acl.d/openshield.json
/etc/init.d/firewall reload
/etc/init.d/rpcd reload
ubus -v list openshield-firewall
```

The rpcd account must be assigned the `openshield` read/write ACL. The ACL grants read-only board/interface discovery and write access only to `block_ip` and `unblock_ip`. Do not grant `file.exec`, unrestricted UCI access, or general shell execution.

Configure the gateway connector with the same `OPENSHIELD_GATEWAY_TOKEN` as the Node. The connector advertises `execute_action` and `verify_action` only when this token is configured. The Node refuses to create firewall policies unless it has encrypted router credentials and a connector advertising both capabilities.

The dashboard policy selector exposes OpenWrt only after router credentials are saved and the authenticated connector has connected. All firewall actions remain approval-gated.

## TTL and recovery

`OPENSHIELD_RESPONSE_WORKER_INTERVAL_SECONDS` controls the Node TTL sweep (default 5 seconds; 0 disables the worker). DNS expiry removes the OpenShield-owned list entry and re-syncs the provider. OpenWrt expiry is enforced locally by nftables element timeout; the Node also queues an explicit rollback and verifies removal. If the connector is offline, the nftables timeout still expires the block.

## Limitations and validation

- OpenWrt enforcement supports public IPv4 only. IPv6, private/LAN IPs, arbitrary nftables rules, and UCI firewall edits are rejected.
- The rpcd plugin and nftables include must be installed manually on the router.
- CI mocks ubus and provider transports; it does not validate the plugin on physical firmware. Follow [the OpenWrt response validation runbook](openwrt-validation.md#10-validate-p5-firewall-actions) on the target device before enabling unattended response.
- Keep Node port 8000 LAN-only unless admin authentication is enabled. Back up `OPENSHIELD_SECRET_KEY`; losing it makes saved router credentials undecryptable.
