import base64
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Body, HTTPException, Query, Request

from openshield.core.metrics import MetricsRegistry
from openshield.core.storage import PostgresStore
from openshield.events.models import EventEnvelope
from openshield.integrations.registry import IntegrationRegistry
from openshield.visibility.normalizers import normalize_sensor_batch


def create_events_router(
    *,
    store: PostgresStore,
    registry: IntegrationRegistry,
    metrics: MetricsRegistry,
    gateway_token_valid: Callable[[Request], bool],
    sensor_token_valid: Callable[[str, Request], bool],
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

    @router.post("/api/v1/events", status_code=202, tags=["events"])
    def ingest_event(event: EventEnvelope, request: Request) -> dict[str, str]:
        if event.source.kind == "openwrt" and not gateway_token_valid(request):
            raise HTTPException(status_code=401, detail="Gateway authentication required")
        integration = registry.get(event.source.integration_id)
        if integration is None:
            raise HTTPException(status_code=400, detail="Unknown source integration")
        if integration.kind != event.source.kind:
            raise HTTPException(status_code=400, detail="Event source kind does not match integration")
        if integration.kind in {"suricata", "zeek"} and not sensor_token_valid(
            integration.integration_id, request
        ):
            store.write_audit(
                "sensor.ingestion.authentication_failed",
                None,
                integration.integration_id,
                {"source": "events"},
            )
            raise HTTPException(status_code=401, detail="Sensor authentication required")
        require_enabled_ingestion(integration.integration_id, integration.enabled, "events")
        inserted = store.insert_event(event)
        if inserted:
            metrics.increment("openshield_events_ingested_total")
        if event.source.kind == "openwrt" and event.event_type == "gateway.discovery":
            store.record_gateway_discovery(
                event.source.integration_id, event.payload, event.observed_at
            )
        return {"status": "accepted" if inserted else "duplicate", "event_id": event.event_id}

    @router.get("/api/v1/events", tags=["events"])
    def list_events(
        integration_id: str | None = None,
        event_type: str | None = None,
        severity: str | None = None,
        limit: Annotated[int, Query(ge=1, le=1000)] = 200,
        cursor: str | None = None,
    ) -> dict[str, object]:
        position = None
        if cursor:
            try:
                raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode()
                timestamp, event_id = raw.split("|", 1)
                position = (datetime.fromisoformat(timestamp), event_id)
            except (ValueError, UnicodeDecodeError) as exc:
                raise HTTPException(status_code=422, detail="Invalid event cursor") from exc
        events, next_position = store.list_events_page(
            integration_id=integration_id,
            event_type=event_type,
            severity=severity,
            limit=limit,
            cursor=position,
        )
        next_cursor = None
        if next_position:
            raw = f"{next_position[0].isoformat()}|{next_position[1]}".encode()
            next_cursor = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        return {
            "items": [event.model_dump(mode="json") for event in events],
            "next_cursor": next_cursor,
        }

    @router.post("/api/v1/sensors/{integration_id}/events", status_code=202, tags=["sensors"])
    def ingest_sensor_events(
        integration_id: str,
        records: Annotated[list[dict[str, Any]], Body()],
        request: Request,
    ) -> dict[str, object]:
        integration = registry.get(integration_id)
        if integration is None or integration.kind not in {"suricata", "zeek"}:
            raise HTTPException(status_code=404, detail="Network sensor integration not found")
        if not sensor_token_valid(integration_id, request):
            store.write_audit(
                "sensor.ingestion.authentication_failed",
                None,
                integration_id,
                {"source": "sensor_events"},
            )
            raise HTTPException(status_code=401, detail="Sensor authentication required")
        require_enabled_ingestion(integration_id, integration.enabled, "sensor_events")
        try:
            events = normalize_sensor_batch(integration.kind, records, integration_id)
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        accepted = duplicates = 0
        for event in events:
            if store.insert_event(event):
                accepted += 1
                metrics.increment("openshield_events_ingested_total")
            else:
                duplicates += 1
        return {"accepted": accepted, "duplicates": duplicates, "received": len(events)}

    @router.get("/api/v1/sensors", tags=["sensors"])
    def list_sensor_health() -> list[dict[str, object]]:
        now = datetime.now(UTC)
        result = []
        stats = store.sensor_event_stats()
        for integration in registry.list_all():
            if integration.kind not in {"suricata", "zeek"}:
                continue
            sensor_stats = stats.get(integration.integration_id, {})
            latest = sensor_stats.get("last_observed_at")
            age = now - latest if latest else None
            result.append({
                "integration_id": integration.integration_id,
                "kind": integration.kind,
                "display_name": integration.display_name,
                "status": "healthy" if age is not None and age <= timedelta(minutes=5)
                    else "stale" if age is not None else "no_data",
                "last_event_at": latest.isoformat() if latest else None,
                "events_seen": sensor_stats.get("events_seen", 0),
                "freshness_basis": "node_observed_at",
            })
        return result

    return router
