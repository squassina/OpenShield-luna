import logging
import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from openshield.core.storage import PostgresStore
from openshield.gateway.registry import GatewayConnectionRegistry
from openshield.integrations.registry import IntegrationRegistry
from openshield.policy.engine import enforcement_enabled, max_autonomy_level
from openshield.privacy.providers import DnsProviderError, sync_provider_lists

logger = logging.getLogger("openshield.execution")


class ExecutionError(RuntimeError):
    pass


def execute_decision(
    store: PostgresStore, registry: IntegrationRegistry,
    gateway_registry: GatewayConnectionRegistry, decision_id: str,
) -> dict[str, object]:
    decision = store.get_policy_decision(decision_id)
    if decision is None:
        raise ValueError("Policy decision not found")
    if decision["status"] != "approved":
        raise ValueError("Only approved policy decisions can execute")
    if store.get_emergency_stop():
        store.update_policy_decision(decision_id, "blocked", {"reason": "emergency_stop_active"})
        raise ExecutionError("Emergency stop is active")
    if not enforcement_enabled():
        store.update_policy_decision(decision_id, "blocked", {"reason": "enforcement_disabled_or_admin_auth_missing"})
        raise ExecutionError("Enforcement requires explicit enablement and admin authentication")

    policy = store.get_policy(str(decision["policy_id"]))
    incident = store.get_incident(str(decision["incident_id"]))
    if policy is None or not policy["enabled"] or incident is None:
        store.update_policy_decision(decision_id, "blocked", {"reason": "policy_or_incident_unavailable"})
        raise ExecutionError("Policy or incident is no longer actionable")
    if incident.get("status") in {"closed", "false_positive"}:
        store.update_policy_decision(decision_id, "blocked", {"reason": "incident_not_actionable"})
        raise ExecutionError("Closed or false-positive incidents cannot be enforced")
    if int(policy["autonomy_level"]) > max_autonomy_level():
        store.update_policy_decision(decision_id, "blocked", {"reason": "autonomy_cap_changed"})
        raise ExecutionError("Global autonomy cap no longer permits this action")

    integration_id = str(policy["integration_id"])
    indicator_type = str(policy["indicator_type"])
    indicator_value = str(policy["indicator_value"])
    if store.has_active_response_execution(indicator_type, indicator_value, integration_id):
        store.update_policy_decision(decision_id, "executed", {"reason": "equivalent_execution_already_active"})
        return {"status": "already_active", "integration_id": integration_id}
    execution_id = str(uuid4())
    ttl_seconds = int(policy["ttl_seconds"])
    action = str(policy["action"])
    direction = str(policy["direction"])

    if action == "block_domain":
        integration = registry.get(integration_id)
        if integration is None or integration.kind not in {"pihole", "adguard"}:
            store.update_policy_decision(decision_id, "failed", {"reason": "dns_integration_unavailable"})
            raise ExecutionError("DNS enforcement integration is unavailable")
        existing = any(
            item.get("list_type") == "block" and item.get("domain") == indicator_value
            for item in store.list_privacy_lists(integration_id)
        )
        now = datetime.now(UTC)
        execution = {
            "execution_id": execution_id, "decision_id": decision_id,
            "incident_id": decision["incident_id"], "policy_id": policy["policy_id"],
            "integration_id": integration_id, "action": action,
            "indicator_type": indicator_type, "indicator_value": indicator_value,
            "direction": direction, "status": "active", "ttl_seconds": ttl_seconds,
            "expires_at": now + timedelta(seconds=ttl_seconds),
            "adapter_result": {"created_by_execution": not existing, "verified": False},
        }
        store.create_response_execution(execution)
        try:
            if not existing:
                store.upsert_privacy_list(
                    integration_id, "block", indicator_value,
                    f"OpenShield managed execution {execution_id}",
                )
            sync_result = sync_provider_lists(integration, store.list_privacy_lists(integration_id))
        except (DnsProviderError, ValueError) as exc:
            if not existing:
                store.update_response_execution(
                    execution_id, "rollback_failed",
                    {"created_by_execution": True, "error": "dns_provider_sync_failed"},
                    expires_at=datetime.now(UTC),
                )
            else:
                store.update_response_execution(
                    execution_id, "failed", {"created_by_execution": False, "error": "dns_provider_sync_failed"},
                )
            store.update_policy_decision(decision_id, "failed", {"reason": "dns_provider_sync_failed"})
            raise ExecutionError("DNS provider did not confirm the block-list update") from exc
        result = store.update_response_execution(
            execution_id, "active",
            {"created_by_execution": not existing, "provider_result": sync_result, "verified": True},
            expires_at=now + timedelta(seconds=ttl_seconds),
        )
        store.update_policy_decision(decision_id, "executed", {"execution_id": execution_id})
        return result or execution

    if action == "block_ip":
        integration = registry.get(integration_id)
        if integration is None or integration.kind != "openwrt":
            store.update_policy_decision(decision_id, "failed", {"reason": "openwrt_integration_unavailable"})
            raise ExecutionError("OpenWrt gateway integration is unavailable")
        if not os.getenv("OPENSHIELD_GATEWAY_TOKEN") or not store.get_integration_secret(integration_id):
            store.update_policy_decision(decision_id, "failed", {"reason": "openwrt_credentials_unavailable"})
            raise ExecutionError("Authenticated OpenWrt gateway credentials are not configured")
        execution = {
            "execution_id": execution_id, "decision_id": decision_id,
            "incident_id": decision["incident_id"], "policy_id": policy["policy_id"],
            "integration_id": integration_id, "action": action,
            "indicator_type": indicator_type, "indicator_value": indicator_value,
            "direction": direction, "status": "pending_gateway", "ttl_seconds": ttl_seconds,
            "expires_at": None, "adapter_result": {},
        }
        store.create_response_execution(execution)
        try:
            store.enqueue_gateway_command(
                str(uuid4()), integration_id, execution_id, "block_ip",
                {"ip": indicator_value, "direction": direction},
            )
        except Exception as exc:
            store.update_response_execution(execution_id, "failed", {"error": "gateway_command_enqueue_failed"})
            store.update_policy_decision(decision_id, "failed", {"reason": "gateway_command_enqueue_failed"})
            raise ExecutionError("Unable to queue the OpenWrt firewall command") from exc
        store.update_policy_decision(decision_id, "executing", {"execution_id": execution_id})
        return execution
    raise ExecutionError("Unsupported enforcement action")


def approve_decision(
    store: PostgresStore, registry: IntegrationRegistry,
    gateway_registry: GatewayConnectionRegistry, decision_id: str,
) -> dict[str, object]:
    decision = store.get_policy_decision(decision_id)
    if decision is None:
        raise ValueError("Policy decision not found")
    if decision["status"] != "pending_approval":
        raise ValueError("Only pending decisions can be approved")
    store.update_policy_decision(decision_id, "approved", {"approval": "human"})
    return execute_decision(store, registry, gateway_registry, decision_id)


def reject_decision(store: PostgresStore, decision_id: str, reason: str) -> dict[str, object]:
    decision = store.get_policy_decision(decision_id)
    if decision is None:
        raise ValueError("Policy decision not found")
    if decision["status"] != "pending_approval":
        raise ValueError("Only pending decisions can be rejected")
    result = store.update_policy_decision(decision_id, "rejected", {"rejection_reason": reason[:500]})
    return result or {}


def process_gateway_command_result(
    store: PostgresStore, command_id: str, status: str, result: dict[str, object]
) -> dict[str, object]:
    command = store.complete_gateway_command(command_id, status, result)
    if command is None:
        raise ValueError("Gateway command not found or already completed")
    execution = store.get_response_execution(str(command["execution_id"]))
    if execution is None:
        raise ValueError("Response execution not found")
    now = datetime.now(UTC)
    if status == "completed" and command["action"] == "block_ip" and result.get("status") == "applied":
        expires_at = now + timedelta(seconds=int(execution["ttl_seconds"]))
        updated = store.update_response_execution(
            execution["execution_id"], "active", result, expires_at=expires_at,
        )
        store.update_policy_decision(execution["decision_id"], "executed", {"execution_id": execution["execution_id"]})
        return updated or execution
    if status == "completed" and command["action"] == "unblock_ip" and result.get("status") == "rolled_back":
        updated = store.update_response_execution(
            execution["execution_id"], "rolled_back", result, rolled_back_at=now,
        )
        return updated or execution
    failed_status = "rollback_failed" if command["action"] == "unblock_ip" else "failed"
    updated = store.update_response_execution(execution["execution_id"], failed_status, result)
    if command["action"] == "block_ip":
        store.update_policy_decision(execution["decision_id"], "failed", {"reason": "gateway_execution_failed"})
    return updated or execution


def expire_due_executions(
    store: PostgresStore, registry: IntegrationRegistry
) -> int:
    due = store.get_due_response_executions()
    processed = 0
    for execution in due:
        integration_id = str(execution["integration_id"])
        if store.has_active_response_execution(
            str(execution["indicator_type"]), str(execution["indicator_value"]),
            integration_id, str(execution["execution_id"]),
        ):
            store.update_response_execution(
                str(execution["execution_id"]), "rolled_back",
                {"rollback": "another_active_execution_retains_the_control"},
                rolled_back_at=datetime.now(UTC),
            )
            processed += 1
            continue
        if execution["action"] == "block_domain":
            if not execution["adapter_result"].get("created_by_execution"):
                store.update_response_execution(
                    str(execution["execution_id"]), "rolled_back",
                    {"rollback": "preexisting_block_entry_preserved"},
                    rolled_back_at=datetime.now(UTC),
                )
                processed += 1
                continue
            integration = registry.get(integration_id)
            try:
                store.delete_privacy_list_item(
                    integration_id, "block", str(execution["indicator_value"]),
                )
                if integration is None:
                    raise ExecutionError("DNS integration no longer exists")
                result = sync_provider_lists(integration, store.list_privacy_lists(integration_id))
                store.update_response_execution(
                    str(execution["execution_id"]), "rolled_back",
                    {"rollback": "dns_block_removed", "provider_result": result},
                    rolled_back_at=datetime.now(UTC),
                )
            except (DnsProviderError, ValueError, ExecutionError):
                store.upsert_privacy_list(
                    integration_id, "block", str(execution["indicator_value"]),
                    f"OpenShield managed execution {execution['execution_id']}",
                )
                store.update_response_execution(
                    str(execution["execution_id"]), "rollback_failed",
                    {"rollback": "dns_provider_unavailable"},
                )
            processed += 1
            continue
        if execution["action"] == "block_ip":
            section = execution["adapter_result"].get("section")
            if not isinstance(section, str):
                store.update_response_execution(
                    str(execution["execution_id"]), "rollback_failed",
                    {"rollback": "missing_gateway_firewall_section"},
                )
                processed += 1
                continue
            if not store.has_pending_gateway_command(str(execution["execution_id"]), "unblock_ip"):
                store.enqueue_gateway_command(
                    str(uuid4()), integration_id, str(execution["execution_id"]), "unblock_ip",
                    {"section": section},
                )
            store.update_response_execution(
                str(execution["execution_id"]), "rollback_pending",
                {"rollback": "gateway_unblock_queued"},
            )
            processed += 1
    return processed
