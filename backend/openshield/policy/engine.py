import ipaddress
import os
from uuid import uuid4

from openshield.core.storage import PostgresStore
from openshield.integrations.registry import IntegrationRegistry
from openshield.privacy.dns import normalize_domain


def create_policy(
    store: PostgresStore, registry: IntegrationRegistry, data: dict[str, object]
) -> dict[str, object]:
    indicator_type = str(data["indicator_type"])
    indicator_value = str(data["indicator_value"])
    action = str(data["action"])
    if action == "block_domain":
        if indicator_type != "domain":
            raise ValueError("block_domain policies require a domain indicator")
        indicator_value = normalize_domain(indicator_value)
    elif action == "block_ip":
        if indicator_type != "ip":
            raise ValueError("block_ip policies require an IP indicator")
        try:
            address = ipaddress.ip_address(indicator_value)
        except ValueError as exc:
            raise ValueError("block_ip policies require a valid IP address") from exc
        if not address.is_global:
            raise ValueError("block_ip policies accept public IP addresses only")
        indicator_value = str(address)
    else:
        raise ValueError("Unsupported policy action")
    integration = registry.get(str(data["integration_id"]))
    if integration is None or not integration.enabled:
        raise ValueError("Policy integration is missing or disabled")
    if action == "block_domain" and integration.kind not in {"pihole", "adguard"}:
        raise ValueError("block_domain requires a Pi-hole or AdGuard integration")
    if action == "block_ip" and integration.kind != "openwrt":
        raise ValueError("block_ip requires an OpenWrt gateway integration")
    if action == "block_ip" and (
        not os.getenv("OPENSHIELD_GATEWAY_TOKEN")
        or not store.get_integration_secret(integration.integration_id)
    ):
        raise ValueError("OpenWrt enforcement requires a gateway token and encrypted router credentials")
    policy = {
        "policy_id": str(uuid4()),
        "name": str(data["name"]).strip(),
        "enabled": bool(data.get("enabled", True)),
        "indicator_type": indicator_type,
        "indicator_value": indicator_value,
        "action": action,
        "integration_id": integration.integration_id,
        "min_risk_score": int(data["min_risk_score"]),
        "autonomy_level": int(data["autonomy_level"]),
        "ttl_seconds": int(data["ttl_seconds"]),
        "require_approval": bool(data.get("require_approval", True)),
        "direction": str(data.get("direction", "destination")),
    }
    if not policy["name"]:
        raise ValueError("Policy name is required")
    return store.create_policy(policy)


def max_autonomy_level() -> int:
    try:
        value = int(os.getenv("OPENSHIELD_MAX_AUTONOMY_LEVEL", "0"))
    except ValueError:
        return 0
    return min(3, max(0, value))


def enforcement_enabled() -> bool:
    return (
        os.getenv("OPENSHIELD_ENFORCEMENT_ENABLED", "false").lower() in {"1", "true", "yes"}
        and os.getenv("OPENSHIELD_API_AUTH_ENABLED", "false").lower() in {"1", "true", "yes"}
    )


def evaluate_policy(
    store: PostgresStore, registry: IntegrationRegistry, incident_id: str, policy_id: str,
    gateway_registry,
) -> dict[str, object]:
    incident = store.get_incident(incident_id)
    policy = store.get_policy(policy_id)
    if incident is None:
        raise ValueError("Incident not found")
    if policy is None:
        raise ValueError("Policy not found")
    reasons = []
    if not policy["enabled"]:
        reasons.append("policy_disabled")
    if incident.get("status") in {"closed", "false_positive"}:
        reasons.append("incident_not_actionable")
    if (
        incident.get("indicator_type") != policy["indicator_type"]
        or incident.get("indicator_value") != policy["indicator_value"]
    ):
        reasons.append("indicator_does_not_match")
    if int(incident.get("risk_score", 0)) < int(policy["min_risk_score"]):
        reasons.append("risk_score_below_threshold")
    if reasons:
        status = "blocked"
    elif int(policy["autonomy_level"]) == 0:
        status = "observe_only"
        reasons.append("autonomy_level_zero")
    elif store.get_emergency_stop():
        status = "blocked"
        reasons.append("emergency_stop_active")
    elif not enforcement_enabled():
        status = "blocked"
        reasons.append("enforcement_disabled_or_admin_auth_missing")
    elif int(policy["autonomy_level"]) > max_autonomy_level():
        status = "blocked"
        reasons.append("autonomy_level_exceeds_global_cap")
    elif bool(policy["require_approval"]) or int(policy["autonomy_level"]) == 1:
        status = "pending_approval"
        reasons.append("human_approval_required")
    else:
        status = "approved"
        reasons.append("policy_allows_bounded_automatic_execution")
    decision = store.create_policy_decision(
        str(uuid4()), incident_id, policy_id, status,
        {
            "reasons": reasons,
            "risk_score": incident.get("risk_score"),
            "policy_minimum": policy["min_risk_score"],
            "policy_autonomy_level": policy["autonomy_level"],
            "global_autonomy_cap": max_autonomy_level(),
            "emergency_stop_active": store.get_emergency_stop(),
            "enforcement_enabled": enforcement_enabled(),
        },
    )
    if status == "approved":
        from openshield.execution.service import execute_decision

        execution = execute_decision(store, registry, gateway_registry, decision["decision_id"])
        return {**decision, "execution": execution}
    return decision
