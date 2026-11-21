import logging
import os
import re
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from openshield.core.storage import PostgresStore
from openshield.gateway.registry import GatewayConnectionRegistry
from openshield.integrations.registry import IntegrationRegistry
from openshield.policy.engine import enforcement_enabled, max_autonomy_level
from openshield.privacy.lists import provider_privacy_lists
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
            for item in provider_privacy_lists(store, integration_id)
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
        if not store.create_response_execution_if_absent(execution):
            store.update_policy_decision(
                decision_id, "executed", {"reason": "equivalent_execution_already_active"},
            )
            return {"status": "already_active", "integration_id": integration_id}
        try:
            if not existing:
                store.upsert_privacy_list(
                    integration_id, "block", indicator_value,
                    f"OpenShield managed execution {execution_id}",
                )
            sync_result = sync_provider_lists(integration, provider_privacy_lists(store, integration_id))
        except (DnsProviderError, ValueError) as exc:
            # Reconcile the provider against the authoritative local list. Remove
            # only the entry created by this execution; preserve manual entries.
            if not existing:
                store.delete_privacy_list_item(
                    integration_id, "block", indicator_value,
                    expected_comment=f"OpenShield managed execution {execution_id}",
                )
            try:
                compensation_result = sync_provider_lists(
                    integration, provider_privacy_lists(store, integration_id),
                )
            except (DnsProviderError, ValueError) as compensation_error:
                logger.error(
                    "DNS enforcement compensation pending execution_id=%s integration_id=%s error=%s",
                    execution_id, integration_id, type(compensation_error).__name__,
                )
                store.update_response_execution(
                    execution_id, "rollback_failed",
                    {
                        "created_by_execution": not existing,
                        "error": "dns_provider_sync_failed",
                        "compensation_status": "pending",
                        "compensation_error": type(compensation_error).__name__,
                    },
                    expires_at=datetime.now(UTC),
                )
            else:
                store.update_response_execution(
                    execution_id, "failed",
                    {
                        "created_by_execution": not existing,
                        "error": "dns_provider_sync_failed",
                        "compensation_status": "completed",
                        "compensation_result": compensation_result,
                    },
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
        if not store.create_response_execution_if_absent(execution):
            store.update_policy_decision(
                decision_id, "executed", {"reason": "equivalent_execution_already_active"},
            )
            return {"status": "already_active", "integration_id": integration_id}
        # Publish the executable decision state before exposing its command to
        # a heartbeat; otherwise a fast Connector could see a false denial.
        store.update_policy_decision(decision_id, "executing", {"execution_id": execution_id})
        try:
            store.enqueue_gateway_command(
                str(uuid4()), integration_id, execution_id, "block_ip",
                {"ip": indicator_value, "direction": direction},
            )
        except Exception as exc:
            store.update_response_execution(execution_id, "failed", {"error": "gateway_command_enqueue_failed"})
            store.update_policy_decision(decision_id, "failed", {"reason": "gateway_command_enqueue_failed"})
            raise ExecutionError("Unable to queue the OpenWrt firewall command") from exc
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
    transitioned = store.transition_policy_decision(
        decision_id, "pending_approval", "approved", {"approval": "human"},
    )
    if transitioned is None:
        raise ValueError("Only pending decisions can be approved")
    return execute_decision(store, registry, gateway_registry, decision_id)


def reject_decision(store: PostgresStore, decision_id: str, reason: str) -> dict[str, object]:
    decision = store.get_policy_decision(decision_id)
    if decision is None:
        raise ValueError("Policy decision not found")
    if decision["status"] != "pending_approval":
        raise ValueError("Only pending decisions can be rejected")
    result = store.transition_policy_decision(
        decision_id, "pending_approval", "rejected", {"rejection_reason": reason[:500]},
    )
    if result is None:
        raise ValueError("Only pending decisions can be rejected")
    return result


def _block_ip_authorization_denial_reason(
    store: PostgresStore,
    execution: dict[str, object],
    *,
    command: dict[str, object] | None = None,
    require_pending: bool = True,
) -> str | None:
    if execution.get("action") != "block_ip" or execution.get("status") != "pending_gateway":
        return "execution_not_pending"
    if command is not None:
        if command.get("action") != "block_ip":
            return "unsupported_command_action"
        if require_pending and command.get("status") != "pending":
            return "command_not_pending"
        created_at = command.get("created_at")
        if not isinstance(created_at, str):
            return "command_created_at_missing"
        try:
            queued_at = datetime.fromisoformat(created_at)
        except ValueError:
            return "command_created_at_invalid"
        if queued_at.tzinfo is None:
            queued_at = queued_at.replace(tzinfo=UTC)
        age_seconds = (datetime.now(UTC) - queued_at).total_seconds()
        if age_seconds < -5 or age_seconds > 60:
            return "command_authorization_lease_expired"
    if store.get_emergency_stop():
        return "emergency_stop_active"
    if not enforcement_enabled():
        return "enforcement_disabled_or_admin_auth_missing"
    policy = store.get_policy(str(execution.get("policy_id")))
    if (
        policy is None or policy.get("enabled") is not True
        or policy.get("action") != "block_ip"
        or policy.get("integration_id") != execution.get("integration_id")
        or policy.get("indicator_type") != execution.get("indicator_type")
        or policy.get("indicator_value") != execution.get("indicator_value")
        or policy.get("direction") != execution.get("direction")
    ):
        return "policy_unavailable_or_changed"
    if int(policy["autonomy_level"]) > max_autonomy_level():
        return "autonomy_cap_changed"
    incident = store.get_incident(str(execution.get("incident_id")))
    if incident is None or incident.get("status") in {"closed", "false_positive"}:
        return "incident_not_actionable"
    decision = store.get_policy_decision(str(execution.get("decision_id")))
    if (
        decision is None or decision.get("status") != "executing"
        or decision.get("policy_id") != execution.get("policy_id")
        or decision.get("incident_id") != execution.get("incident_id")
    ):
        return "policy_decision_not_executable"
    return None


def authorize_gateway_command(
    store: PostgresStore, gateway_id: str, command_id: str,
) -> dict[str, object]:
    command = store.get_gateway_command(command_id)
    if command is None or command.get("gateway_id") != gateway_id:
        return {"authorized": False, "reason": "command_unavailable", "lease_seconds": 0}
    if command.get("status") != "pending":
        return {"authorized": False, "reason": "command_not_pending", "lease_seconds": 0}
    execution = store.get_response_execution(str(command["execution_id"]))
    if execution is None or execution.get("integration_id") != gateway_id:
        return {"authorized": False, "reason": "execution_unavailable", "lease_seconds": 0}
    if command.get("action") == "unblock_ip":
        payload = command.get("payload")
        section = payload.get("section") if isinstance(payload, dict) else None
        adapter_result = execution.get("adapter_result")
        expected = adapter_result.get("section") if isinstance(adapter_result, dict) else None
        authorized = (
            execution.get("action") == "block_ip"
            and execution.get("status") in {"active", "rollback_pending", "rollback_failed"}
            and isinstance(section, str)
            and re.fullmatch(r"os_[a-f0-9]{1,16}", section) is not None
            and section == expected
        )
        return {
            "authorized": authorized,
            "reason": None if authorized else "rollback_not_owned_by_execution",
            "lease_seconds": 10 if authorized else 0,
        }
    if command.get("action") != "block_ip":
        return {"authorized": False, "reason": "unsupported_command_action", "lease_seconds": 0}
    reason = _block_ip_authorization_denial_reason(
        store, execution, command=command, require_pending=True,
    )
    return {"authorized": reason is None, "reason": reason, "lease_seconds": 10 if reason is None else 0}


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
        denial_reason = _block_ip_authorization_denial_reason(
            store, execution, command=command, require_pending=False,
        )
        section = result.get("section")
        if denial_reason is not None:
            if isinstance(section, str) and re.fullmatch(r"os_[a-f0-9]{1,16}", section):
                if not store.has_pending_gateway_command(execution["execution_id"], "unblock_ip"):
                    store.enqueue_gateway_command(
                        str(uuid4()), str(execution["integration_id"]),
                        str(execution["execution_id"]), "unblock_ip", {"section": section},
                    )
                updated = store.update_response_execution(
                    execution["execution_id"], "rollback_pending",
                    {"section": section, "rollback": "authorization_revoked_after_apply",
                     "authorization_reason": denial_reason},
                    expires_at=now,
                )
            else:
                updated = store.update_response_execution(
                    execution["execution_id"], "rollback_failed",
                    {"rollback": "applied_rule_section_unavailable",
                     "authorization_reason": denial_reason},
                    expires_at=now,
                )
            store.update_policy_decision(
                execution["decision_id"], "blocked",
                {"reason": "gateway_authorization_revoked", "authorization_reason": denial_reason},
            )
            return updated or execution
        if not isinstance(section, str) or not re.fullmatch(r"os_[a-f0-9]{1,16}", section):
            updated = store.update_response_execution(
                execution["execution_id"], "rollback_failed",
                {"rollback": "applied_rule_section_invalid"}, expires_at=now,
            )
            store.update_policy_decision(
                execution["decision_id"], "blocked",
                {"reason": "gateway_returned_invalid_firewall_section"},
            )
            return updated or execution
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
        if (
            execution["action"] == "block_domain"
            and execution["adapter_result"].get("compensation_status") == "pending"
        ):
            integration = registry.get(integration_id)
            try:
                if integration is None:
                    raise ExecutionError("DNS integration no longer exists")
                if execution["adapter_result"].get("created_by_execution"):
                    store.delete_privacy_list_item(
                        integration_id, "block", str(execution["indicator_value"]),
                        expected_comment=(
                            f"OpenShield managed execution {execution['execution_id']}"
                        ),
                    )
                result = sync_provider_lists(
                    integration, provider_privacy_lists(store, integration_id),
                )
                store.update_response_execution(
                    str(execution["execution_id"]), "failed",
                    {
                        **execution["adapter_result"],
                        "compensation_status": "completed",
                        "compensation_result": result,
                    },
                )
            except (DnsProviderError, ValueError, ExecutionError) as exc:
                logger.error(
                    "DNS enforcement compensation still pending execution_id=%s integration_id=%s error=%s",
                    execution["execution_id"], integration_id, type(exc).__name__,
                )
                store.update_response_execution(
                    str(execution["execution_id"]), "rollback_failed",
                    {
                        **execution["adapter_result"],
                        "compensation_status": "pending",
                        "compensation_error": type(exc).__name__,
                    },
                    expires_at=datetime.now(UTC),
                )
            processed += 1
            continue
        # Each execution owns its own firewall section. Always remove this
        # execution's section; another execution must not orphan this rule.
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
            deleted = False
            try:
                deleted = store.delete_privacy_list_item(
                    integration_id, "block", str(execution["indicator_value"]),
                    expected_comment=(
                        f"OpenShield managed execution {execution['execution_id']}"
                    ),
                )
                if integration is None:
                    raise ExecutionError("DNS integration no longer exists")
                result = sync_provider_lists(integration, provider_privacy_lists(store, integration_id))
                store.update_response_execution(
                    str(execution["execution_id"]), "rolled_back",
                    {"rollback": "dns_block_removed", "provider_result": result},
                    rolled_back_at=datetime.now(UTC),
                )
            except (DnsProviderError, ValueError, ExecutionError):
                if deleted:
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
