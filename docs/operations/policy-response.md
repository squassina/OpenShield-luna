# Policy and bounded response

OpenShield P5 is a deterministic enforcement layer. It does not use AI output as policy authority. No policy is created automatically from an incident.

## 1. Safe defaults

| Control | Default | Meaning |
|---|---|---|
| `OPENSHIELD_ENFORCEMENT_ENABLED` | `false` | No response action can execute |
| `OPENSHIELD_API_AUTH_ENABLED` | `false` | Must be enabled with admin credentials before enforcement |
| `OPENSHIELD_MAX_AUTONOMY_LEVEL` | `0` | Observe only |
| Emergency stop | Active | Blocks all new execution |
| Policy approval | Required | Default for every policy |
| Action TTL | 1 hour | Configurable 60–86,400 seconds |

To enable enforcement, first configure strong HTTP Basic credentials and the shared gateway token. Set `OPENSHIELD_ENFORCEMENT_ENABLED=true`, choose a global autonomy cap, and release the emergency stop through the authenticated API. Never expose Node or router management RPC to the Internet.

## 2. Autonomy levels

- **L0 — Observe:** evaluate and record a policy decision; never execute.
- **L1 — Human approval:** every matching action waits for explicit approval.
- **L2 — Bounded automation:** execute only when the policy explicitly sets `require_approval=false` and the global cap permits L2.
- **L3 — Explicit high autonomy:** same technical gates as L2, but only when the global cap is deliberately set to 3 and the exact policy is configured for L3.

The global cap is a hard ceiling. A policy above the cap is blocked. The emergency stop is active by default and blocks new execution regardless of autonomy level. Releasing it requires both enforcement enablement and authenticated administration.

## 3. Create exact-match policies

Policies require:
- Exact public IP or normalized domain indicator.
- Matching action: `block_ip` for OpenWrt; `block_domain` for Pi-hole/AdGuard.
- Minimum incident risk score (0–100).
- Explicit autonomy level, approval requirement, direction, and TTL.
- No wildcard or CIDR policy matching.

Example DNS policy:

```bash
curl -X POST http://localhost:8000/api/v1/policies \
  -H 'Content-Type: application/json' \
  --data '{
    "name":"Temporary block for confirmed tracker IOC",
    "indicator_type":"domain",
    "indicator_value":"malicious.example",
    "action":"block_domain",
    "integration_id":"pihole-home",
    "min_risk_score":80,
    "autonomy_level":1,
    "require_approval":true,
    "ttl_seconds":3600
  }'
```

Evaluate an incident against a policy:

```bash
curl -X POST http://localhost:8000/api/v1/incidents/<incident-id>/evaluate \
  -H 'Content-Type: application/json' \
  --data '{"policy_id":"<policy-id>"}'
```

L1 decisions enter `pending_approval`. Approve or reject explicitly:

```bash
curl -X POST http://localhost:8000/api/v1/policy-decisions/<decision-id>/approve
curl -X POST http://localhost:8000/api/v1/policy-decisions/<decision-id>/reject \
  -H 'Content-Type: application/json' --data '{"reason":"Not approved"}'
```

## 4. DNS execution

A `block_domain` policy adds an OpenShield-managed entry to the configured Pi-hole/AdGuard block list and synchronizes the provider. The execution record notes whether OpenShield created the entry. TTL rollback removes only entries created by that execution; pre-existing manual blocks are preserved.

If provider synchronization fails, the execution enters `rollback_failed` and the expiry worker retries the cleanup. The API never reports a provider block as active without a successful sync response.

## 5. OpenWrt firewall execution

A `block_ip` policy requires:
- An OpenWrt integration with encrypted router credentials.
- `OPENSHIELD_GATEWAY_TOKEN` configured on Node and connector.
- A Gateway Connector that can retrieve and report authenticated commands.
- A dedicated rpcd ACL permitting only required UCI methods on the `firewall` config.

The Node queues only two allowlisted command types: `block_ip` and `unblock_ip`. The Gateway Connector validates the command shape and invokes scoped UCI operations; it exposes no shell or arbitrary ubus command execution.

- `direction=source`: WAN-to-LAN source IP.
- `direction=destination`: LAN-to-WAN destination IP.
- Firewall target: `REJECT`.
- UCI changes use `apply` with rollback protection, verification, then `confirm`.
- Node starts TTL only after the connector reports verified application.
- TTL expiry queues the matching UCI deletion through the authenticated connector channel.

Physical hardware validation of the ACL, UCI behavior, firewall4 direction and rollback is mandatory before production enforcement. CI uses mocked ubus and does not prove router behavior.

## 6. TTL, rollback, and emergency stop

The Node expiry worker runs every 15 seconds. Expired DNS actions are synchronized back out. Expired firewall actions queue a gateway rollback command. Failed rollbacks remain visible as `rollback_failed` and are retried; do not ignore them.

Emergency stop is active by default:

```bash
curl http://localhost:8000/api/v1/control/emergency-stop
curl -X POST http://localhost:8000/api/v1/control/emergency-stop \
  -H 'Content-Type: application/json' --data '{"active":true}'
```

Releasing it (`active=false`) requires `OPENSHIELD_ENFORCEMENT_ENABLED=true` and authenticated administration. Activating it is always permitted. It blocks new actions; it does not prevent rollback of already-active actions.

## 7. Audit and operations

Inspect:
- `GET /api/v1/policies`
- `GET /api/v1/policy-decisions`
- `GET /api/v1/executions`
- `GET /api/v1/audit`

Every policy creation/update, decision, approval/rejection, execution, gateway command, status transition, and emergency-stop change is audited. Enforcement is never inferred from AI confidence or recommendations.
