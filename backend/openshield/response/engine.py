from datetime import UTC, datetime, timedelta
from uuid import uuid4

from openshield.core.storage import PostgresStore
from openshield.integrations.models import Integration
from openshield.integrations.registry import IntegrationRegistry
from openshield.privacy.dns import normalize_domain
from openshield.privacy.providers import DnsProviderError, sync_provider_lists


RESPONSE_LIST_ID = "openshield-local"
RESPONSE_COMMENT_PREFIX = "OpenShield response:"


def _update(
    store: PostgresStore,
    action: dict[str, object],
    status: str,
    *,
    expires_at=None,
    next_attempt_at=None,
    attempts: int | None = None,
    **changes: object,
) -> dict[str, object]:
    payload = {**action, **changes, "status": status, "updated_at": datetime.now(UTC).isoformat()}
    result = store.update_response_action(
        str(action["action_id"]), payload, expires_at=expires_at,
        next_attempt_at=next_attempt_at, attempts=attempts,
    )
    if result is None:
        raise ValueError("Response action not found")
    return result


def _provider(
    registry: IntegrationRegistry, integration_id: str
) -> Integration:
    integration = registry.get(integration_id)
    if integration is None or integration.kind not in {"pihole", "adguard"}:
        raise ValueError("Response policy DNS provider is unavailable")
    if not integration.enabled:
        raise ValueError("Response policy DNS provider is disabled")
    return integration


def execute_dns_block(
    store: PostgresStore, registry: IntegrationRegistry, action: dict[str, object]
) -> dict[str, object]:
    if action.get("status") != "approved":
        raise ValueError("Response action must be approved before execution")
    if store.get_response_control()["kill_switch_enabled"]:
        return _update(
            store, action, "blocked_by_kill_switch",
            error="Global response kill switch is enabled",
        )
    if action.get("indicator_type") != "domain":
        return _update(store, action, "failed", error="unsupported_indicator_type")
    try:
        domain = normalize_domain(action.get("indicator_value"))
        provider = _provider(registry, str(action.get("provider_integration_id", "")))
    except (TypeError, ValueError) as exc:
        return _update(store, action, "failed", error=str(exc)[:200])

    entries = store.list_privacy_lists(RESPONSE_LIST_ID)
    existing = next(
        (item for item in entries if item["list_type"] == "block" and item["domain"] == domain),
        None,
    )
    marker = RESPONSE_COMMENT_PREFIX + str(action["action_id"])
    if existing is not None:
        return _update(
            store, action, "already_enforced",
            verification={"provider": provider.kind, "already_blocked": True},
            expires_at=None,
        )

    store.upsert_privacy_list(RESPONSE_LIST_ID, "block", domain, marker)
    try:
        result = sync_provider_lists(
            provider, store.list_privacy_lists(RESPONSE_LIST_ID),
        )
    except (DnsProviderError, ValueError, TypeError):
        # Compensate local state if provider synchronization fails.
        store.delete_privacy_list_item(RESPONSE_LIST_ID, "block", domain)
        try:
            sync_provider_lists(provider, store.list_privacy_lists(RESPONSE_LIST_ID))
            error = "provider_sync_failed; local change reverted"
        except (DnsProviderError, ValueError, TypeError):
            error = "provider_sync_and_compensation_failed; inspect provider state"
        return _update(store, action, "failed", error=error, expires_at=None)

    expires_at = datetime.now(UTC) + timedelta(seconds=int(action["ttl_seconds"]))
    return _update(
        store, action, "active", expires_at=expires_at,
        verification={
            "provider": result.get("provider"),
            "added": result.get("added", 0),
            "removed": result.get("removed", 0),
            "readback_verified": True,
        },
        executed_at=datetime.now(UTC).isoformat(),
        expires_at_display=expires_at.isoformat(),
        error=None,
    )


def rollback_action(
    store: PostgresStore,
    registry: IntegrationRegistry,
    action_id: str,
    *,
    reason: str = "administrator_requested",
) -> dict[str, object]:
    action = store.get_response_action(action_id)
    if action is None:
        raise ValueError("Response action not found")
    if action.get("status") in {"rolled_back", "already_enforced", "rejected", "cancelled_by_kill_switch"}:
        return action
    if action.get("status") not in {"active", "rollback_pending"}:
        raise ValueError("Only active response actions can be rolled back")

    domain = normalize_domain(action.get("indicator_value"))
    entries = store.list_privacy_lists(RESPONSE_LIST_ID)
    existing = next(
        (item for item in entries if item["list_type"] == "block" and item["domain"] == domain),
        None,
    )
    marker = RESPONSE_COMMENT_PREFIX + action_id
    if existing is None:
        return _update(
            store, action, "rolled_back", expires_at=None, next_attempt_at=None,
            rollback_reason=reason, rollback_at=datetime.now(UTC).isoformat(),
            verification={**(action.get("verification") or {}), "entry_already_absent": True},
        )
    if existing.get("comment") != marker:
        return _update(
            store, action, "rollback_conflict", expires_at=None, next_attempt_at=None,
            error="block entry ownership changed; manual review required",
        )

    provider = _provider(registry, str(action.get("provider_integration_id", "")))
    store.delete_privacy_list_item(RESPONSE_LIST_ID, "block", domain)
    try:
        result = sync_provider_lists(provider, store.list_privacy_lists(RESPONSE_LIST_ID))
    except (DnsProviderError, ValueError, TypeError):
        # Restore the local managed entry so the desired state remains explicit.
        store.upsert_privacy_list(RESPONSE_LIST_ID, "block", domain, marker)
        attempts = int(action.get("attempts", 0)) + 1
        retry_at = datetime.now(UTC) + timedelta(seconds=min(300, 5 * (2 ** min(attempts, 6))))
        return _update(
            store, action, "rollback_pending", expires_at=datetime.now(UTC),
            next_attempt_at=retry_at, attempts=attempts,
            error="provider_rollback_failed; retry scheduled",
        )
    return _update(
        store, action, "rolled_back", expires_at=None, next_attempt_at=None,
        rollback_reason=reason, rollback_at=datetime.now(UTC).isoformat(),
        verification={
            "provider": result.get("provider"),
            "removed": result.get("removed", 0),
            "readback_verified": True,
        },
        error=None,
    )


def evaluate_incident(
    store: PostgresStore,
    registry: IntegrationRegistry,
    incident_id: str,
) -> dict[str, object]:
    incident = store.get_incident(incident_id)
    if incident is None:
        raise ValueError("Incident not found")
    if incident.get("status") in {"closed", "false_positive"}:
        return {"incident_id": incident_id, "actions": [], "skipped": "incident_not_actionable"}

    control = store.get_response_control()
    actions: list[dict[str, object]] = []
    for policy in store.list_response_policies():
        if not policy.get("enabled"):
            continue
        if incident.get("indicator_type") != "domain":
            continue
        if int(incident.get("risk_score", 0)) < int(policy.get("min_risk_score", 100)):
            continue
        try:
            provider = _provider(registry, str(policy.get("provider_integration_id", "")))
        except ValueError:
            continue

        requires_approval = bool(policy.get("approval_required")) or int(incident.get("risk_score", 0)) >= 80
        status = (
            "blocked_by_kill_switch" if control["kill_switch_enabled"]
            else "pending_approval" if requires_approval
            else "approved"
        )
        action = {
            "action_id": str(uuid4()),
            "policy_id": policy["policy_id"],
            "policy_name": policy["name"],
            "incident_id": incident_id,
            "indicator_type": "domain",
            "indicator_value": incident["indicator_value"],
            "action_type": "dns_block_domain",
            "provider_integration_id": provider.integration_id,
            "ttl_seconds": int(policy["ttl_seconds"]),
            "approval_required": requires_approval,
            "status": status,
            "requested_at": datetime.now(UTC).isoformat(),
            "approved_at": None,
            "executed_at": None,
            "expires_at": None,
            "verification": None,
            "error": None,
        }
        created, inserted = store.create_response_action(action)
        if inserted and status == "approved":
            created = execute_dns_block(store, registry, created)
        actions.append(created)
    return {"incident_id": incident_id, "actions": actions}


def approve_action(
    store: PostgresStore, registry: IntegrationRegistry, action_id: str,
    actor_id: str | None = None,
) -> dict[str, object]:
    if store.get_response_control()["kill_switch_enabled"]:
        raise ValueError("Global response kill switch is enabled")
    action = store.get_response_action(action_id)
    if action is None:
        raise ValueError("Response action not found")
    if action.get("status") != "pending_approval":
        raise ValueError("Response action is not awaiting approval")
    approved = _update(
        store, action, "approved", approved_at=datetime.now(UTC).isoformat(),
        approved_by=actor_id or "local-admin",
    )
    return execute_dns_block(store, registry, approved)


def reject_action(store: PostgresStore, action_id: str, actor_id: str | None = None) -> dict[str, object]:
    action = store.get_response_action(action_id)
    if action is None:
        raise ValueError("Response action not found")
    if action.get("status") != "pending_approval":
        raise ValueError("Response action is not awaiting approval")
    return _update(
        store, action, "rejected", expires_at=None,
        rejected_at=datetime.now(UTC).isoformat(), rejected_by=actor_id or "local-admin",
    )


def set_kill_switch(
    store: PostgresStore, registry: IntegrationRegistry, enabled: bool, reason: str = ""
) -> dict[str, object]:
    control = store.set_response_control(enabled, reason)
    if not enabled:
        return {**control, "rolled_back": 0, "rollback_pending": 0}

    cancelled = 0
    for action in store.list_response_actions(limit=500, status="pending_approval"):
        _update(
            store, action, "cancelled_by_kill_switch", expires_at=None,
            cancelled_at=datetime.now(UTC).isoformat(),
        )
        cancelled += 1
    rolled_back = pending = 0
    for action in store.list_active_response_actions():
        result = rollback_action(
            store, registry, str(action["action_id"]), reason="global_kill_switch",
        )
        if result.get("status") == "rollback_pending":
            pending += 1
        elif result.get("status") == "rolled_back":
            rolled_back += 1
    return {**control, "cancelled_pending": cancelled, "rolled_back": rolled_back, "rollback_pending": pending}


def expire_due_actions(store: PostgresStore, registry: IntegrationRegistry) -> dict[str, int]:
    expired = pending = 0
    for action in store.list_due_response_actions():
        result = rollback_action(
            store, registry, str(action["action_id"]), reason="ttl_expired",
        )
        if result.get("status") == "rolled_back":
            expired += 1
        elif result.get("status") == "rollback_pending":
            pending += 1
    return {"expired": expired, "rollback_pending": pending}
