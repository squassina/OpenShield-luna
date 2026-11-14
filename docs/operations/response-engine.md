# P5 — Deterministic response engine

## Supported action in this phase

P5 introduces deterministic response policies and a separate execution layer. The first supported enforcement action is **domain blocking through one configured Pi-hole v6 or AdGuard Home integration**.

A policy defines:
- Minimum incident risk score (0–100).
- DNS provider integration.
- Block TTL (60 seconds to 7 days).
- Whether human approval is required.

Policies apply only to domain indicators. IP and firewall actions are deliberately rejected/not offered until the OpenWrt connector has a narrowly scoped, independently verifiable firewall API. No arbitrary command execution or broad router configuration writes are used.

## Safety behavior

- No policy is created by default; an administrator must explicitly create and enable one.
- Incidents marked closed or false positive are not actionable.
- Risk score >= 80 always requires human approval, even if a policy requests automatic execution.
- The global kill switch blocks new execution, cancels pending approvals, and attempts rollback of all active OpenShield response actions.
- A DNS block is written to the OpenShield-managed local list, synchronized to one selected provider, and read-back verified by the provider adapter.
- If synchronization fails, the local list mutation is compensated. If rollback synchronization fails, the action enters `rollback_pending` and retries with bounded exponential backoff.
- Each executed block has an expiry timestamp. The response worker removes only the list entry bearing that action's ownership marker; pre-existing/manual blocks are never removed.
- Every policy/action/approval/rejection/rollback/kill-switch transition is audited.

## Configuration

`OPENSHIELD_RESPONSE_WORKER_INTERVAL_SECONDS` controls the TTL sweep (default 5 seconds; 0 disables the worker). Keep the Node API LAN-only unless administrative authentication is enabled.

## Limitations

The current action adapter covers DNS domain blocks only. It does not block IP addresses or alter OpenWrt firewall rules. Physical provider and router behavior must be validated against the target hardware before enabling unattended response in production.
