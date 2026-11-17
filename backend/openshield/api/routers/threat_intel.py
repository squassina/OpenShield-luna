import ipaddress
from collections.abc import Callable
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, Query

from openshield.api.schemas import ThreatIntelEnrichRequest
from openshield.core.secrets import SecretConfigurationError, SecretStore
from openshield.core.storage import PostgresStore
from openshield.integrations.misp import MispClient, MispError
from openshield.integrations.registry import IntegrationRegistry
from openshield.threat_intel.engine import enrich_events

SSLContextKwargs = Callable[[object, str], dict[str, object]]
ThreatIntelEnricher = Callable[[PostgresStore, IntegrationRegistry, list[str]], dict[str, object]]


def create_threat_intel_router(
    *,
    store: PostgresStore,
    registry: IntegrationRegistry,
    ssl_context_kwargs: SSLContextKwargs,
    enrich: ThreatIntelEnricher = enrich_events,
) -> APIRouter:
    router = APIRouter()

    @router.post("/api/v1/integrations/{integration_id}/misp-sync", tags=["integrations"])
    def sync_misp_indicators(
        integration_id: str, limit: int = Query(default=1000, ge=1, le=1000)
    ) -> dict[str, object]:
        integration = registry.get(integration_id)
        if integration is None or integration.kind != "misp":
            raise HTTPException(status_code=404, detail="MISP integration not found")
        if not integration.enabled:
            raise HTTPException(status_code=409, detail="MISP integration is disabled")
        try:
            credentials = SecretStore(store).get(integration_id)
            if credentials is None:
                raise HTTPException(status_code=409, detail="MISP credentials are not configured")
            client = MispClient(
                str(credentials["base_url"]), str(credentials["api_key"]),
                **ssl_context_kwargs(integration, str(credentials["base_url"])),
            )
            indicators = client.search_indicators(limit)
            complete_snapshot = len(indicators) < limit
            sync_result = store.sync_threat_indicators(
                integration_id, indicators, complete_snapshot=complete_snapshot
            )
            return {
                "status": "synced",
                "integration_id": integration_id,
                "received": len(indicators),
                "stored": sync_result["stored"],
                "removed": sync_result["removed"],
                "limit": limit,
                "truncated_possible": not complete_snapshot,
                "reconciled": complete_snapshot,
            }
        except SecretConfigurationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=422,
                detail="Stored MISP credentials or sync parameters are invalid",
            ) from exc
        except MispError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    @router.get("/api/v1/threat-intel/indicators", tags=["threat-intel"])
    def list_threat_indicators(
        integration_id: str | None = None,
        limit: int = Query(default=200, ge=1, le=1000),
    ) -> dict[str, object]:
        items = store.list_threat_indicators(integration_id=integration_id, limit=limit)
        return {"items": items, "count": len(items)}

    @router.get("/api/v1/threat-intel/matches", tags=["threat-intel"])
    def list_threat_matches(
        event_limit: int = Query(default=500, ge=1, le=1000),
        indicator_limit: int = Query(default=1000, ge=1, le=1000),
    ) -> dict[str, object]:
        indicators = store.list_threat_indicators(limit=indicator_limit)
        events = store.list_events(limit=event_limit)
        matches = []
        for event in events:
            payload = event.payload
            observed: dict[str, set[str]] = {"ip": set(), "domain": set()}
            for field in ("src_ip", "dest_ip", "id.orig_h", "id.resp_h"):
                value = payload.get(field)
                if isinstance(value, str):
                    try:
                        observed["ip"].add(str(ipaddress.ip_address(value)))
                    except ValueError:
                        pass
            for field in ("domain", "query", "hostname", "host", "url"):
                value = payload.get(field)
                if not isinstance(value, str) or not value.strip():
                    continue
                candidate = value.strip()
                if field == "url" or "://" in candidate:
                    try:
                        candidate = urlsplit(candidate).hostname or ""
                    except ValueError:
                        candidate = ""
                candidate = candidate.rstrip(".").lower()
                if candidate and "/" not in candidate and " " not in candidate:
                    observed["domain"].add(candidate)
            for indicator in indicators:
                indicator_type = indicator["indicator_type"]
                value = str(indicator["value"])
                if indicator_type in {"ip-src", "ip-dst"}:
                    try:
                        matched = str(ipaddress.ip_address(value)) in observed["ip"]
                    except ValueError:
                        matched = False
                elif indicator_type in {"domain", "hostname"}:
                    matched = value.rstrip(".").lower() in observed["domain"]
                else:
                    matched = False
                if matched:
                    matches.append({
                        "indicator": indicator,
                        "event": {
                            "event_id": event.event_id,
                            "event_type": event.event_type,
                            "occurred_at": event.occurred_at.isoformat(),
                            "source": event.source.model_dump(mode="json"),
                        },
                        "match_type": "exact",
                        "assessment": "threat_intelligence_match",
                    })
        return {
            "items": matches,
            "count": len(matches),
            "events_scanned": len(events),
            "indicators_scanned": len(indicators),
            "note": "Exact IOC matches only; no autonomous blocking or inferred attribution.",
        }

    @router.post("/api/v1/threat-intel/enrich", tags=["threat-intelligence"])
    def enrich_threat_indicators(request: ThreatIntelEnrichRequest) -> dict[str, object]:
        try:
            return enrich(store, registry, list(dict.fromkeys(request.event_ids)))
        except SecretConfigurationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    return router
