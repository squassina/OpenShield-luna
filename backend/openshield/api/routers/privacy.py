from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Body, HTTPException, Query, Response
from pydantic import BaseModel, Field

from openshield.core.metrics import MetricsRegistry
from openshield.core.secrets import SecretConfigurationError, SecretStore
from openshield.core.storage import PostgresStore
from openshield.integrations.registry import IntegrationRegistry
from openshield.privacy.dns import normalize_dns_batch, normalize_domain
from openshield.privacy.lists import provider_privacy_lists
from openshield.privacy.polling import (
    _record_poll_attempt,
    _record_poll_failure,
    _record_poll_success,
    get_poll_status,
    reset_poll_status,
)
from openshield.privacy.providers import DnsProviderError, fetch_dns_records, sync_provider_lists


class PrivacyListEntry(BaseModel):
    list_type: str = Field(pattern=r"^(allow|block)$")
    domain: str = Field(min_length=3, max_length=253)
    comment: str = Field(default="", max_length=500)


class ClassificationOverrideRequest(BaseModel):
    action: Literal["allow", "tracker"]
    reason: str = Field(default="", max_length=500)


def create_privacy_router(
    *,
    store: PostgresStore,
    registry: IntegrationRegistry,
    metrics: MetricsRegistry,
) -> APIRouter:
    router = APIRouter()

    def require_enabled_ingestion(integration_id: str, enabled: bool, source: str) -> None:
        if enabled:
            return
        store.write_audit(
            "integration.ingestion.rejected",
            None,
            integration_id,
            {"source": source, "reason": "integration_disabled"},
        )
        raise HTTPException(
            status_code=409,
            detail="Integration is disabled; new ingestion is rejected",
        )

    def get_dns_integration(integration_id: str):
        integration = registry.get(integration_id)
        if integration is None or integration.kind not in {"pihole", "adguard"}:
            raise HTTPException(status_code=404, detail="DNS privacy integration not found")
        return integration

    @router.post("/api/v1/dns/{integration_id}/queries", status_code=202, tags=["privacy"])
    def ingest_dns_queries(
        integration_id: str,
        records: Annotated[list[dict[str, Any]], Body()],
    ) -> dict[str, object]:
        integration = get_dns_integration(integration_id)
        require_enabled_ingestion(integration_id, integration.enabled, "dns_queries")
        try:
            events = normalize_dns_batch(
                integration.kind, integration_id, records,
                store.list_privacy_classification_overrides(),
            )
        except (ValueError, TypeError, OverflowError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        accepted = duplicates = 0
        for event in events:
            if store.insert_event(event):
                accepted += 1
                metrics.increment("openshield_events_ingested_total")
            else:
                duplicates += 1
        return {"accepted": accepted, "duplicates": duplicates, "received": len(events)}

    @router.post("/api/v1/privacy/sources/{integration_id}/sync", status_code=202, tags=["privacy"])
    def sync_privacy_source(integration_id: str) -> dict[str, object]:
        integration = get_dns_integration(integration_id)
        require_enabled_ingestion(integration_id, integration.enabled, "dns_manual_sync")
        _record_poll_attempt(integration_id)
        try:
            encrypted = store.get_integration_secret(integration_id)
            credentials = SecretStore(store).get(integration_id) if encrypted else None
            records = fetch_dns_records(integration, credentials)
            events = normalize_dns_batch(
                integration.kind, integration_id, records,
                store.list_privacy_classification_overrides(),
            ) if records else []
        except SecretConfigurationError as exc:
            _record_poll_failure(integration_id)
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except (DnsProviderError, ValueError, TypeError, OverflowError) as exc:
            _record_poll_failure(integration_id)
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        accepted = duplicates = 0
        for event in events:
            if store.insert_event(event):
                accepted += 1
                metrics.increment("openshield_events_ingested_total")
            else:
                duplicates += 1
        _record_poll_success(integration_id, accepted, duplicates)
        store.write_audit(
            "privacy.provider_poll.completed", None, integration_id,
            {"provider": integration.kind, "received": len(events),
             "accepted": accepted, "duplicates": duplicates, "trigger": "manual"},
        )
        return {"accepted": accepted, "duplicates": duplicates, "received": len(events)}

    @router.delete("/api/v1/privacy/sources/{integration_id}/cursor", tags=["privacy"])
    def reset_privacy_source_cursor(integration_id: str) -> dict[str, str]:
        integration = get_dns_integration(integration_id)
        store.delete_integration_poll_cursor(integration_id)
        reset_poll_status(integration_id)
        store.write_audit(
            "privacy.provider_poll.cursor_reset", None, integration_id,
            {"provider": integration.kind, "reason": "administrator_requested"},
        )
        return {"status": "reset", "integration_id": integration_id}

    @router.get("/api/v1/privacy/sources", tags=["privacy"])
    def list_privacy_sources() -> list[dict[str, object]]:
        now = datetime.now(UTC)
        stats = store.privacy_source_stats()
        result = []
        for integration in registry.list_all():
            if integration.kind not in {"pihole", "adguard"}:
                continue
            source = stats.get(integration.integration_id, {})
            latest = source.get("last_observed_at")
            poll = get_poll_status(integration.integration_id)
            last_success = poll.get("last_success_at")
            last_success_at = datetime.fromisoformat(last_success) if isinstance(last_success, str) else None
            success_age = now - last_success_at if last_success_at else None
            observed_age = now - latest if latest else None
            source_status = (
                "disabled" if not integration.enabled
                else "failed" if poll.get("status") == "failed"
                else "healthy" if (success_age is not None and success_age <= timedelta(minutes=5))
                    or (success_age is None and observed_age is not None and observed_age <= timedelta(minutes=5))
                else "stale" if last_success_at or latest
                else "no_data"
            )
            result.append({
                "integration_id": integration.integration_id,
                "kind": integration.kind,
                "display_name": integration.display_name,
                "status": source_status,
                "last_query_at": latest.isoformat() if latest else None,
                "last_attempt_at": poll.get("last_attempt_at"),
                "last_success_at": last_success,
                "last_failure_at": poll.get("last_failure_at"),
                "last_imported": poll.get("last_imported", 0),
                "last_duplicates": poll.get("last_duplicates", 0),
                "last_rejected": poll.get("last_rejected", 0),
                "last_error": poll.get("last_error"),
                "last_error_category": poll.get("last_error_category"),
                "retryable": poll.get("retryable"),
                "queries_seen": source.get("queries_seen", 0),
                "freshness_basis": "node_observed_at",
            })
        return result

    @router.get("/api/v1/privacy/analytics/domains", tags=["privacy"])
    def privacy_domain_analytics(
        days: Annotated[int, Query(ge=1, le=365)] = 30,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ) -> list[dict[str, object]]:
        return store.privacy_domain_stats(days, limit)

    @router.get("/api/v1/privacy/analytics/devices", tags=["privacy"])
    def privacy_device_analytics(
        days: Annotated[int, Query(ge=1, le=365)] = 30,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ) -> list[dict[str, object]]:
        return store.privacy_client_stats(days, limit)

    @router.get("/api/v1/privacy/trends", tags=["privacy"])
    def privacy_trends(
        days: Annotated[int, Query(ge=1, le=365)] = 30,
    ) -> list[dict[str, object]]:
        return store.privacy_trends(days)

    @router.get("/api/v1/privacy/report", tags=["privacy"])
    def privacy_report(
        days: Annotated[int, Query(ge=1, le=365)] = 30,
    ) -> dict[str, object]:
        trends = store.privacy_trends(days)
        domains = store.privacy_domain_stats(days, 10)
        devices = store.privacy_client_stats(days, 10)
        queries = sum(item["queries"] for item in trends)
        blocked = sum(item["blocked"] for item in trends)
        tracker_queries = sum(item["tracker_queries"] for item in trends)
        totals = {
            "queries": queries, "blocked": blocked, "tracker_queries": tracker_queries,
            "block_rate_percent": round(blocked * 100 / queries, 2) if queries else 0.0,
            "tracker_rate_percent": round(tracker_queries * 100 / queries, 2) if queries else 0.0,
        }
        return {
            "period_days": days, "generated_at": datetime.now(UTC).isoformat(),
            "totals": totals, "top_domains": domains, "top_devices": devices,
            "daily_trends": trends,
            "classification_notice": "Domain classification is heuristic and is not a threat verdict.",
        }

    @router.get("/api/v1/privacy/lists", tags=["privacy"])
    def list_privacy_lists(integration_id: str | None = None) -> list[dict[str, object]]:
        return store.list_privacy_lists(integration_id)

    @router.get("/api/v1/privacy/classifications/overrides", tags=["privacy"])
    def list_classification_overrides() -> dict[str, dict[str, object]]:
        return store.list_privacy_classification_overrides()

    @router.put("/api/v1/privacy/classifications/overrides/{domain}", tags=["privacy"])
    def set_classification_override(
        domain: str, request: ClassificationOverrideRequest
    ) -> dict[str, object]:
        try:
            normalized = normalize_domain(domain)
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        store.upsert_privacy_classification_override(normalized, request.action, request.reason)
        return store.list_privacy_classification_overrides()[normalized]

    @router.delete("/api/v1/privacy/classifications/overrides/{domain}", tags=["privacy"])
    def delete_classification_override(domain: str) -> Response:
        try:
            normalized = normalize_domain(domain)
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if not store.delete_privacy_classification_override(normalized):
            raise HTTPException(status_code=404, detail="Classification override not found")
        return Response(status_code=204)

    @router.post("/api/v1/privacy/lists", status_code=201, tags=["privacy"])
    def add_privacy_list_entry(entry: PrivacyListEntry) -> dict[str, object]:
        try:
            domain = normalize_domain(entry.domain)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        store.upsert_privacy_list("openshield-local", entry.list_type, domain, entry.comment)
        return {
            "integration_id": "openshield-local", "list_type": entry.list_type,
            "domain": domain, "comment": entry.comment,
        }

    @router.post("/api/v1/privacy/lists/{integration_id}/sync", status_code=200, tags=["privacy"])
    def sync_privacy_lists(integration_id: str) -> dict[str, object]:
        integration = get_dns_integration(integration_id)
        entries = provider_privacy_lists(store, integration_id)
        try:
            encrypted = store.get_integration_secret(integration_id)
            credentials = SecretStore(store).get(integration_id) if encrypted else None
            result = sync_provider_lists(integration, entries, credentials)
        except SecretConfigurationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except DnsProviderError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        store.write_audit(
            "privacy.provider_lists.synchronized", None, integration_id,
            {"provider": integration.kind, "entry_count": len(entries), "result": result},
        )
        return {"integration_id": integration_id, "entries": len(entries), **result}

    @router.delete("/api/v1/privacy/lists/{list_type}/{domain}", status_code=204, tags=["privacy"])
    def remove_privacy_list_entry(list_type: str, domain: str) -> Response:
        if list_type not in {"allow", "block"}:
            raise HTTPException(status_code=422, detail="list_type must be allow or block")
        try:
            normalized = normalize_domain(domain)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if not store.delete_privacy_list_item("openshield-local", list_type, normalized):
            raise HTTPException(status_code=404, detail="Privacy list entry not found")
        return Response(status_code=204)

    return router
