import asyncio
import base64
import ipaddress
import os
import secrets
import threading
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from fastapi import Body, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from psycopg_pool import PoolTimeout
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from openshield.ai.orchestrator import investigate_incident
from openshield.ai.providers import AIProviderError
from openshield.api.routers.gateway import create_gateway_router
from openshield.api.routers.health import create_health_router
from openshield.api.routers.integration_credentials import create_integration_credentials_router
from openshield.api.routers.integration_tests import create_integration_test_router
from openshield.api.routers.integrations import create_integrations_router
from openshield.api.routers.metrics import create_metrics_router
from openshield.api.schemas import (
    AdGuardCredentials,
    AIProviderCredentials,
    CrowdSecCredentials,
    GrafanaCredentials,
    MispCredentials,
    OPNsenseCredentials,
    OpenWrtCredentials,
    PfSenseCredentials,
    PiHoleCredentials,
    PrometheusCredentials,
    ThreatIntelCredentials,
    WazuhCredentials,
)
__all__ = ["AdGuardCredentials","AIProviderCredentials","CrowdSecCredentials","GrafanaCredentials","MispCredentials","OPNsenseCredentials","OpenWrtCredentials","PfSenseCredentials","PiHoleCredentials","PrometheusCredentials","ThreatIntelCredentials","WazuhCredentials"]

from openshield.core.bootstrap import load_runtime_secrets
from openshield.core.logging import configure_logging
from openshield.core.metrics import MetricsRegistry
from openshield.core.request_limits import RequestBodyLimitMiddleware
from openshield.core.secrets import SecretConfigurationError, SecretStore
from openshield.core.storage import PostgresStore
from openshield.core.tls import CABundleError, create_ssl_context
from openshield.events.models import EventEnvelope
from openshield.execution.service import (
    ExecutionError,
    approve_decision,
    reject_decision,
)
from openshield.execution.worker import run_expiration_loop
from openshield.gateway.registry import GatewayConnectionRegistry
from openshield.integrations.ai import AIProviderAdapter
from openshield.integrations.grafana import GrafanaAdapter
from openshield.integrations.misp import MispClient, MispError
from openshield.integrations.openwrt import OpenWrtAdapter
from openshield.integrations.opnsense import OPNsenseAdapter
from openshield.integrations.pfsense import PfSenseAdapter
from openshield.integrations.prometheus import PrometheusAdapter
from openshield.integrations.registry import IntegrationRegistry
from openshield.integrations.threat_intel import ThreatIntelAdapter
from openshield.integrations.wazuh import WazuhAdapter
from openshield.policy.engine import (
    create_policy,
    enforcement_enabled,
    evaluate_policy,
    max_autonomy_level,
)
from openshield.privacy.adapter import DnsPrivacyAdapter
from openshield.privacy.dns import normalize_dns_batch, normalize_domain
from openshield.privacy.lists import provider_privacy_lists
from openshield.privacy.polling import (
    _record_poll_attempt,
    _record_poll_failure,
    _record_poll_success,
    get_poll_status,
    reset_poll_status,
    run_dns_polling_loop,
)
from openshield.privacy.providers import DnsProviderError, fetch_dns_records, sync_provider_lists
from openshield.threat_intel.engine import enrich_events
from openshield.visibility.adapter import NetworkSensorAdapter
from openshield.visibility.normalizers import normalize_sensor_batch

load_runtime_secrets(create=True)
configure_logging()

@asynccontextmanager
async def _dns_polling_lifespan(app: FastAPI):
    interval_raw = os.getenv("OPENSHIELD_DNS_POLL_INTERVAL_SECONDS", "60")
    try:
        interval = int(interval_raw)
    except ValueError as exc:
        raise RuntimeError("OPENSHIELD_DNS_POLL_INTERVAL_SECONDS must be an integer") from exc
    if interval < 0 or interval > 86400:
        raise RuntimeError("OPENSHIELD_DNS_POLL_INTERVAL_SECONDS must be between 0 and 86400")
    store.open()
    task = asyncio.create_task(run_dns_polling_loop(registry, store, metrics, interval)) if interval else None
    execution_task = asyncio.create_task(run_expiration_loop(store, registry))
    try:
        yield
    finally:
        try:
            for background_task in (task, execution_task):
                if background_task is not None:
                    background_task.cancel()
                    try:
                        await background_task
                    except asyncio.CancelledError:
                        pass
        finally:
            store.close()


app = FastAPI(
    title="OpenShield Node API",
    version="0.1.0",
    description="Gateway-first network security and privacy intelligence node.",
    lifespan=_dns_polling_lifespan,
)

@app.exception_handler(PoolTimeout)
async def database_pool_timeout_handler(_request: Request, _exc: PoolTimeout) -> JSONResponse:
    return JSONResponse(
        {"detail": "Database connection pool is busy; retry shortly"},
        status_code=503,
        headers={"Retry-After": "1"},
    )

app.add_middleware(RequestBodyLimitMiddleware, max_body_bytes=5 * 1024 * 1024)


def _integration_ssl_context(integration, url: str):
    try:
        return create_ssl_context(integration.config.get("ca_bundle_path"), url)
    except CABundleError as exc:
        raise ValueError("Configured integration CA bundle is invalid") from exc


def _integration_ssl_context_kwargs(integration, url: str) -> dict[str, object]:
    context = _integration_ssl_context(integration, url)
    return {"ssl_context": context} if context is not None else {}


def _gateway_openwrt_config(gateway_id: str) -> dict[str, object] | None:
    credentials = SecretStore(store).get(gateway_id)
    integration = registry.get(gateway_id)
    ca_bundle_path = integration.config.get("ca_bundle_path") if integration is not None else None
    if credentials is not None and integration is not None:
        if ca_bundle_path:
            credentials["ca_bundle_path"] = ca_bundle_path
        firewall_zones = integration.config.get("firewall_zones")
        if firewall_zones is not None:
            credentials["firewall_zones"] = firewall_zones
    return credentials


_AUTH_FAILURE_WINDOW_SECONDS = 60
_AUTH_FAILURE_MAX_ENTRIES = 4096
_AUTH_FAILURES: dict[str, tuple[float, int]] = {}
_AUTH_FAILURES_LOCK = threading.Lock()


def _prune_auth_failures_locked(now: float) -> None:
    expired = [
        remote
        for remote, (window, _) in _AUTH_FAILURES.items()
        if now - window >= _AUTH_FAILURE_WINDOW_SECONDS
    ]
    for remote in expired:
        _AUTH_FAILURES.pop(remote, None)
    while len(_AUTH_FAILURES) > _AUTH_FAILURE_MAX_ENTRIES:
        _AUTH_FAILURES.pop(next(iter(_AUTH_FAILURES)))


def _record_auth_failure(remote: str, now: float) -> None:
    with _AUTH_FAILURES_LOCK:
        _prune_auth_failures_locked(now)
        window, failures = _AUTH_FAILURES.get(remote, (now, 0))
        if now - window >= _AUTH_FAILURE_WINDOW_SECONDS:
            window, failures = now, 0
        if remote in _AUTH_FAILURES:
            _AUTH_FAILURES.pop(remote)
        elif len(_AUTH_FAILURES) >= _AUTH_FAILURE_MAX_ENTRIES:
            _AUTH_FAILURES.pop(next(iter(_AUTH_FAILURES)))
        _AUTH_FAILURES[remote] = (window, failures + 1)


def _gateway_token_valid(request: Request) -> bool:
    expected = os.getenv("OPENSHIELD_GATEWAY_TOKEN", "")
    supplied = request.headers.get("authorization", "")
    return bool(expected and supplied.startswith("Bearer ") and secrets.compare_digest(
        supplied[7:], expected
    ))


def _api_auth_enabled() -> bool:
    return os.getenv("OPENSHIELD_API_AUTH_ENABLED", "false").strip().lower() in {"1", "true", "yes"}


def _check_admin_auth(request: Request) -> Response | None:
    if not _api_auth_enabled():
        return None
    username = os.getenv("OPENSHIELD_API_USERNAME", "")
    password = os.getenv("OPENSHIELD_API_PASSWORD", "")
    if not username or not password:
        return JSONResponse(
            {"detail": "API authentication is enabled but credentials are not configured"},
            status_code=503,
        )
    remote = request.client.host if request.client else "unknown"
    now = time.monotonic()
    with _AUTH_FAILURES_LOCK:
        _prune_auth_failures_locked(now)
        window, failures = _AUTH_FAILURES.get(remote, (now, 0))
        if now - window >= _AUTH_FAILURE_WINDOW_SECONDS:
            window, failures = now, 0
        if failures >= 5:
            return JSONResponse({"detail": "Too many authentication attempts"}, status_code=429)
    header = request.headers.get("authorization", "")
    valid = False
    if header.startswith("Basic "):
        try:
            decoded = base64.b64decode(header[6:], validate=True).decode("utf-8")
            supplied_user, supplied_password = decoded.split(":", 1)
            valid = secrets.compare_digest(supplied_user, username) and secrets.compare_digest(
                supplied_password, password
            )
        except (ValueError, UnicodeDecodeError):
            valid = False
    if not valid:
        _record_auth_failure(remote, now)
        return JSONResponse(
            {"detail": "Authentication required"},
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="OpenShield", charset="UTF-8"'},
        )
    with _AUTH_FAILURES_LOCK:
        _AUTH_FAILURES.pop(remote, None)
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if request.headers.get("sec-fetch-site", "").lower() == "cross-site":
            return JSONResponse({"detail": "Cross-site state change rejected"}, status_code=403)
        origin = request.headers.get("origin")
        if origin:
            try:
                parsed = urlsplit(origin)
            except ValueError:
                parsed = None
            if (
                parsed is None or parsed.netloc != request.headers.get("host")
                or parsed.scheme not in {"http", "https"}
            ):
                return JSONResponse({"detail": "Cross-origin state change rejected"}, status_code=403)
    return None


@app.middleware("http")
async def authenticate_requests(request: Request, call_next):
    path = request.url.path
    if path.startswith("/health/") or path == "/metrics":
        return await call_next(request)
    is_gateway = path.startswith("/api/v1/gateway/")
    if is_gateway:
        response = (
            JSONResponse({"detail": "Gateway authentication required"}, status_code=401)
            if not _gateway_token_valid(request)
            else await call_next(request)
        )
    else:
        denied = _check_admin_auth(request)
        response = denied if denied is not None else await call_next(request)
    if is_gateway or path.endswith(("-credentials", "-diagnostics")):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
    return response


@app.middleware("http")
async def collect_http_metrics(request: Request, call_next) -> Response:
    try:
        response = await call_next(request)
    except Exception:
        route = request.scope.get("route")
        metrics.increment(
            "openshield_http_requests_total",
            {
                "method": request.method,
                "route": getattr(route, "path", "unmatched"),
                "status": "500",
            },
        )
        raise
    route = request.scope.get("route")
    metrics.increment(
        "openshield_http_requests_total",
        {
            "method": request.method,
            "route": getattr(route, "path", "unmatched"),
            "status": str(response.status_code),
        },
    )
    return response


store = PostgresStore(
    os.getenv("OPENSHIELD_DATABASE_URL", ""),
    pool_min_size=int(os.getenv("OPENSHIELD_DB_POOL_MIN_SIZE", "1")),
    pool_max_size=int(os.getenv("OPENSHIELD_DB_POOL_MAX_SIZE", "10")),
    pool_timeout=float(os.getenv("OPENSHIELD_DB_POOL_TIMEOUT_SECONDS", "5")),
)
registry = IntegrationRegistry(store)
gateway_connections = GatewayConnectionRegistry(store)
metrics = MetricsRegistry()

app.include_router(create_health_router(store))
app.include_router(create_metrics_router(metrics))
app.include_router(
    create_gateway_router(
        store=store,
        registry=registry,
        gateway_connections=gateway_connections,
        metrics=metrics,
        gateway_openwrt_config=_gateway_openwrt_config,
        gateway_token_valid=_gateway_token_valid,
    )
)
adapters = {
    "openwrt": OpenWrtAdapter(),
    "opnsense": OPNsenseAdapter(),
    "pfsense": PfSenseAdapter(),
    "crowdsec": ThreatIntelAdapter("crowdsec"),
    "misp": ThreatIntelAdapter("misp"),
    "wazuh": WazuhAdapter(),
    "prometheus": PrometheusAdapter(),
    "grafana": GrafanaAdapter(),
    "suricata": NetworkSensorAdapter("suricata"),
    "zeek": NetworkSensorAdapter("zeek"),
    "pihole": DnsPrivacyAdapter("pihole"),
    "adguard": DnsPrivacyAdapter("adguard"),
    "ollama": AIProviderAdapter("ollama"),
    "openai": AIProviderAdapter("openai"),
}


class PrivacyListEntry(BaseModel):
    list_type: str = Field(pattern=r"^(allow|block)$")
    domain: str = Field(min_length=3, max_length=253)
    comment: str = Field(default="", max_length=500)


class ClassificationOverrideRequest(BaseModel):
    action: Literal["allow", "tracker"]
    reason: str = Field(default="", max_length=500)


class ThreatIntelEnrichRequest(BaseModel):
    event_ids: list[str] = Field(min_length=1, max_length=100)


class IncidentStatusRequest(BaseModel):
    status: Literal["open", "acknowledged", "closed", "false_positive"]
    reason: str = Field(default="", max_length=500)


class AIInvestigationRequest(BaseModel):
    provider_id: str = Field(min_length=2, max_length=64)


class PolicyCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    enabled: bool = True
    indicator_type: Literal["ip", "domain"]
    indicator_value: str = Field(min_length=3, max_length=253)
    action: Literal["block_ip", "block_domain"]
    integration_id: str = Field(min_length=2, max_length=64)
    min_risk_score: int = Field(ge=0, le=100)
    autonomy_level: int = Field(ge=0, le=3, default=0)
    ttl_seconds: int = Field(ge=60, le=86400, default=3600)
    require_approval: bool = True
    direction: Literal["source", "destination"] = "destination"


class PolicyUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    enabled: bool | None = None
    min_risk_score: int | None = Field(default=None, ge=0, le=100)
    autonomy_level: int | None = Field(default=None, ge=0, le=3)
    ttl_seconds: int | None = Field(default=None, ge=60, le=86400)
    require_approval: bool | None = None
    direction: Literal["source", "destination"] | None = None


class PolicyEvaluationRequest(BaseModel):
    policy_id: str = Field(min_length=2, max_length=64)


class PolicyDecisionRejectionRequest(BaseModel):
    reason: str = Field(default="", max_length=500)


class EmergencyStopRequest(BaseModel):
    active: bool


DASHBOARD_PATH = Path(__file__).resolve().parents[1] / "dashboard.html"


@app.get("/", response_class=FileResponse, include_in_schema=False)
def dashboard() -> FileResponse:
    if not DASHBOARD_PATH.is_file():
        raise HTTPException(status_code=404, detail="Dashboard asset not found")
    return FileResponse(DASHBOARD_PATH, media_type="text/html")


app.include_router(
    create_integrations_router(store=store, registry=registry, adapters=adapters)
)


app.include_router(
    create_integration_test_router(
        store=store,
        registry=registry,
        ssl_context_kwargs=_integration_ssl_context_kwargs,
    )
)


app.include_router(
    create_integration_credentials_router(
        store=store,
        registry=registry,
        ssl_context_kwargs=_integration_ssl_context_kwargs,
    )
)


@app.post("/api/v1/integrations/{integration_id}/misp-sync", tags=["integrations"])
def sync_misp_indicators(
    integration_id: str, limit: Annotated[int, Query(ge=1, le=1000)] = 1000
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
            **_integration_ssl_context_kwargs(integration, str(credentials["base_url"])),
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
        raise HTTPException(status_code=422, detail="Stored MISP credentials or sync parameters are invalid") from exc
    except MispError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.get("/api/v1/threat-intel/indicators", tags=["threat-intel"])
def list_threat_indicators(
    integration_id: str | None = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
) -> dict[str, object]:
    items = store.list_threat_indicators(integration_id=integration_id, limit=limit)
    return {"items": items, "count": len(items)}


@app.get("/api/v1/threat-intel/matches", tags=["threat-intel"])
def list_threat_matches(
    event_limit: Annotated[int, Query(ge=1, le=1000)] = 500,
    indicator_limit: Annotated[int, Query(ge=1, le=1000)] = 1000,
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


@app.post("/api/v1/incidents/{incident_id}/investigate", tags=["ai"])
def investigate_incident_route(
    incident_id: str, request: AIInvestigationRequest
) -> dict[str, object]:
    try:
        return investigate_incident(store, registry, incident_id, request.provider_id)
    except AIProviderError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except SecretConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/v1/incidents/{incident_id}/investigations", tags=["ai"])
def list_incident_investigations(incident_id: str) -> list[dict[str, object]]:
    if store.get_incident(incident_id) is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return store.list_incident_investigations(incident_id, limit=20)


@app.post("/api/v1/threat-intel/enrich", tags=["threat-intelligence"])
def enrich_threat_indicators(request: ThreatIntelEnrichRequest) -> dict[str, object]:
    try:
        return enrich_events(store, registry, list(dict.fromkeys(request.event_ids)))
    except SecretConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/v1/incidents", tags=["incidents"])
def list_incidents(
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    status: str | None = None,
) -> list[dict[str, object]]:
    if status is not None and status not in {"open", "acknowledged", "closed", "false_positive"}:
        raise HTTPException(status_code=422, detail="Invalid incident status")
    return store.list_incidents(limit=limit, status=status)


@app.get("/api/v1/incidents/{incident_id}", tags=["incidents"])
def get_incident(incident_id: str) -> dict[str, object]:
    incident = store.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {
        **incident,
        "timeline": [event.model_dump(mode="json") for event in store.get_incident_events(incident_id)],
    }


@app.patch("/api/v1/incidents/{incident_id}", tags=["incidents"])
def update_incident_status(
    incident_id: str, request: IncidentStatusRequest
) -> dict[str, object]:
    incident = store.update_incident_status(incident_id, request.status, request.reason)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@app.get("/api/v1/policies", tags=["policy"])
def list_policies() -> dict[str, object]:
    return {
        "items": store.list_policies(),
        "max_autonomy_level": max_autonomy_level(),
        "enforcement_enabled": enforcement_enabled(),
        "emergency_stop_active": store.get_emergency_stop(),
    }


@app.post("/api/v1/policies", status_code=201, tags=["policy"])
def register_policy(request: PolicyCreateRequest) -> dict[str, object]:
    try:
        return create_policy(store, registry, request.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.patch("/api/v1/policies/{policy_id}", tags=["policy"])
def patch_policy(policy_id: str, request: PolicyUpdateRequest) -> dict[str, object]:
    if store.get_policy(policy_id) is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    result = store.update_policy(policy_id, request.model_dump(exclude_unset=True, exclude_none=True))
    if result is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    return result


@app.get("/api/v1/policy-decisions", tags=["policy"])
def list_policy_decisions(
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> list[dict[str, object]]:
    return store.list_policy_decisions(limit)


@app.get("/api/v1/executions", tags=["execution"])
def list_response_executions(
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> list[dict[str, object]]:
    return store.list_response_executions(limit)


@app.get("/api/v1/control/emergency-stop", tags=["execution"])
def get_emergency_stop() -> dict[str, object]:
    return {
        "active": store.get_emergency_stop(),
        "enforcement_enabled": enforcement_enabled(),
        "max_autonomy_level": max_autonomy_level(),
    }


@app.post("/api/v1/control/emergency-stop", tags=["execution"])
def set_emergency_stop(request: EmergencyStopRequest) -> dict[str, object]:
    if not request.active and not enforcement_enabled():
        raise HTTPException(
            status_code=403,
            detail="Releasing emergency stop requires enforcement enablement and authenticated administration",
        )
    store.set_emergency_stop(request.active)
    return {"active": store.get_emergency_stop()}


@app.post("/api/v1/incidents/{incident_id}/evaluate", tags=["policy"])
def evaluate_incident_policy(
    incident_id: str, request: PolicyEvaluationRequest
) -> dict[str, object]:
    try:
        return evaluate_policy(
            store, registry, incident_id, request.policy_id, gateway_connections,
        )
    except ExecutionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/v1/policy-decisions/{decision_id}/approve", tags=["policy"])
def approve_policy_decision(decision_id: str) -> dict[str, object]:
    try:
        return approve_decision(store, registry, gateway_connections, decision_id)
    except ExecutionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/v1/policy-decisions/{decision_id}/reject", tags=["policy"])
def reject_policy_decision(
    decision_id: str, request: PolicyDecisionRejectionRequest
) -> dict[str, object]:
    try:
        return reject_decision(store, decision_id, request.reason)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/v1/integrations/{integration_id}/test", tags=["integrations"])
def test_openwrt_connector(integration_id: str) -> dict[str, object]:
    integration = registry.get(integration_id)
    if integration is None or integration.kind != "openwrt":
        raise HTTPException(status_code=404, detail="OpenWrt integration not found")
    if not integration.config.get("rpc_configured"):
        raise HTTPException(status_code=409, detail="OpenWrt credentials are not configured")
    gateway = gateway_connections.get_status(integration_id)
    if gateway is None or gateway.get("status") != "connected":
        return {
            "status": "connector_disconnected",
            "message": "Gateway Connector is not connected. Check its deployment and OPENSHIELD_GATEWAY_TOKEN.",
        }
    health_events = store.list_events(integration_id, "gateway.health", limit=1)
    discovery_events = store.list_events(integration_id, "gateway.discovery", limit=1)
    discovery = discovery_events[0] if discovery_events else None
    router = discovery.payload if discovery else None
    last_discovery = discovery.observed_at.isoformat() if discovery else None
    if health_events:
        health = health_events[0]
        age_seconds = max(0, int((datetime.now(UTC) - health.observed_at).total_seconds()))
        diagnostics = {
            "last_rpc_check": health.observed_at.isoformat(),
            "last_rpc_check_age_seconds": age_seconds,
            "last_discovery_at": last_discovery,
            "router": router,
            "gateway": gateway,
        }
        if health.payload.get("status") == "reachable":
            if age_seconds > 90:
                return {
                    "status": "router_rpc_stale",
                    "message": "The last successful OpenWrt RPC check is older than 90 seconds. Check connector heartbeat and router reachability.",
                    **diagnostics,
                }
            return {
                "status": "router_rpc_connected",
                "message": "Gateway Connector and OpenWrt RPC are responding.",
                **diagnostics,
            }
        if health.payload.get("status") == "unavailable":
            return {
                "status": "router_rpc_failed",
                "message": "Gateway Connector is online but OpenWrt RPC failed. Check router URL, RPC credentials, read-only rpcd ACL permissions and TLS trust.",
                **diagnostics,
            }
    return {
        "status": "connector_connected",
        "message": "Gateway Connector is online. Waiting for its first OpenWrt RPC health check.",
        "last_discovery_at": last_discovery,
        "router": router,
        "gateway": gateway,
    }


def _require_enabled_ingestion(
    integration_id: str, enabled: bool, source: str,
) -> None:
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


@app.post("/api/v1/events", status_code=202, tags=["events"])
def ingest_event(event: EventEnvelope, request: Request) -> dict[str, str]:
    if (
        event.source.kind == "openwrt"
        and not _gateway_token_valid(request)
    ):
        raise HTTPException(status_code=401, detail="Gateway authentication required")
    integration = registry.get(event.source.integration_id)
    if integration is None:
        raise HTTPException(status_code=400, detail="Unknown source integration")
    if integration.kind != event.source.kind:
        raise HTTPException(status_code=400, detail="Event source kind does not match integration")
    _require_enabled_ingestion(integration.integration_id, integration.enabled, "events")
    inserted = store.insert_event(event)
    if inserted:
        metrics.increment("openshield_events_ingested_total")
    if event.source.kind == "openwrt" and event.event_type == "gateway.discovery":
        store.record_gateway_discovery(
            event.source.integration_id, event.payload, event.observed_at
        )
    return {"status": "accepted" if inserted else "duplicate", "event_id": event.event_id}


@app.get("/api/v1/events", tags=["events"])
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
        integration_id=integration_id, event_type=event_type,
        severity=severity, limit=limit, cursor=position,
    )
    next_cursor = None
    if next_position:
        raw = f"{next_position[0].isoformat()}|{next_position[1]}".encode()
        next_cursor = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    return {"items": [event.model_dump(mode="json") for event in events], "next_cursor": next_cursor}


@app.post("/api/v1/sensors/{integration_id}/events", status_code=202, tags=["sensors"])
def ingest_sensor_events(
    integration_id: str,
    records: Annotated[list[dict[str, Any]], Body()],
) -> dict[str, object]:
    integration = registry.get(integration_id)
    if integration is None or integration.kind not in {"suricata", "zeek"}:
        raise HTTPException(status_code=404, detail="Network sensor integration not found")
    _require_enabled_ingestion(integration_id, integration.enabled, "sensor_events")
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


@app.get("/api/v1/sensors", tags=["sensors"])
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


def _classify_ip(value: object) -> tuple[str, str] | None:
    if not isinstance(value, str):
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if address.is_unspecified or address.is_multicast:
        return None
    if address.is_loopback:
        scope = "loopback"
    elif address.is_link_local:
        scope = "link_local"
    elif address.is_private:
        scope = "private"
    elif address.is_global:
        scope = "public"
    else:
        scope = "reserved"
    return str(address), scope


@app.get("/api/v1/inventory/router-devices", tags=["inventory"])
def list_router_devices(
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
) -> dict[str, object]:
    now = datetime.now(UTC)
    snapshots = store.list_gateway_discovery_snapshots()
    devices = []
    for item in store.list_gateway_devices(limit=limit):
        last_seen = item["last_seen_at"]
        devices.append({
            **item["payload"],
            "gateway_id": item["gateway_id"],
            "mac_address": item["mac_address"],
            "first_seen": item["first_seen_at"].isoformat(),
            "last_seen": last_seen.isoformat(),
            "status": "online" if now - last_seen <= timedelta(seconds=90) else "offline",
        })
    return {
        "gateways": [
            {
                "gateway_id": item["gateway_id"],
                "observed_at": item["observed_at"].isoformat(),
                **item["payload"],
            }
            for item in snapshots
        ],
        "devices": devices,
    }

def _identity_index(now: datetime) -> dict[str, dict[str, object]]:
    candidates: dict[str, list[dict[str, object]]] = {}
    for item in store.list_device_identity_observations():
        address = _classify_ip(item["ip_address"])
        if address is None:
            continue
        candidates.setdefault(address[0], []).append(item)

    result: dict[str, dict[str, object]] = {}
    for address, observations in candidates.items():
        by_device: dict[tuple[str, str], dict[str, object]] = {}
        for item in observations:
            key = (str(item["gateway_id"]), str(item["mac_address"]))
            candidate = by_device.setdefault(key, {
                "gateway_id": item["gateway_id"],
                "mac_address": item["mac_address"],
                "first_seen": item["first_seen_at"],
                "last_seen": item["last_seen_at"],
                "sources": set(),
                "confidence": "low",
            })
            candidate["sources"].add(item["source"])
            if item["confidence"] == "high" or (
                item["confidence"] == "medium" and candidate["confidence"] == "low"
            ):
                candidate["confidence"] = item["confidence"]
            candidate["first_seen"] = min(candidate["first_seen"], item["first_seen_at"])
            candidate["last_seen"] = max(candidate["last_seen"], item["last_seen_at"])

        normalized = []
        for candidate in by_device.values():
            last_seen = candidate["last_seen"]
            normalized.append({
                **candidate,
                "sources": sorted(candidate["sources"]),
                "first_seen": candidate["first_seen"].isoformat(),
                "last_seen": last_seen.isoformat(),
                "status": "current" if now - last_seen <= timedelta(seconds=90) else "stale",
            })
        current = [item for item in normalized if item["status"] == "current"]
        status = (
            "conflict" if len(current) > 1
            else "identified" if len(current) == 1
            else "stale" if normalized else "unknown"
        )
        result[address] = {
            "identity_status": status,
            "identity_candidates": sorted(
                normalized, key=lambda item: (item["gateway_id"], item["mac_address"])
            ),
            "current_identity": current[0] if len(current) == 1 else None,
        }
    return result


def _network_segments() -> list[dict[str, object]]:
    segments = []
    for snapshot in store.list_gateway_discovery_snapshots():
        interfaces = snapshot["payload"].get("interfaces", [])
        if not isinstance(interfaces, list):
            continue
        for interface in interfaces:
            if not isinstance(interface, dict):
                continue
            subnets = interface.get("subnets", [])
            if not isinstance(subnets, list):
                continue
            for subnet in subnets:
                if not isinstance(subnet, dict) or not isinstance(subnet.get("subnet"), str):
                    continue
                try:
                    network = ipaddress.ip_network(subnet["subnet"], strict=False)
                except ValueError:
                    continue
                vlan_id = interface.get("vlan_id")
                if (
                    not isinstance(vlan_id, int)
                    or isinstance(vlan_id, bool)
                    or not 1 <= vlan_id <= 4094
                ):
                    vlan_id = None
                segments.append({
                    "subnet": str(network),
                    "ip_version": network.version,
                    "prefix_length": network.prefixlen,
                    "gateway_id": snapshot["gateway_id"],
                    "interface": interface.get("name"),
                    "device": interface.get("device"),
                    "vlan_id": vlan_id,
                    "gateway_addresses": interface.get("gateway_addresses", []),
                    "source": "openwrt.network.interface.dump",
                    "confidence": "high",
                })
    return segments


def _node_metadata(
    address: str,
    identities: dict[str, dict[str, object]],
    segments: list[dict[str, object]],
    device_index: dict[tuple[str, str], dict[str, object]],
) -> dict[str, object]:
    identity = identities.get(address, {})
    current = identity.get("current_identity")
    metadata: dict[str, object] = {
        "ip_address": address,
        "scope": _classify_ip(address)[1],
        "ip_version": ipaddress.ip_address(address).version,
        "identity_status": identity.get("identity_status", "unknown"),
        "identity_candidates": identity.get("identity_candidates", []),
    }
    if isinstance(current, dict):
        device = device_index.get((current["gateway_id"], current["mac_address"]), {})
        metadata.update({
            "mac_address": current["mac_address"],
            "hostname": device.get("name"),
            "vendor": device.get("vendor"),
            "gateway_id": current["gateway_id"],
            "interface": device.get("interface"),
            "identity_sources": current["sources"],
            "identity_confidence": current["confidence"],
            "identity_first_seen": current["first_seen"],
            "identity_last_seen": current["last_seen"],
        })
    matching_segments = []
    parsed = ipaddress.ip_address(address)
    for segment in segments:
        try:
            network = ipaddress.ip_network(segment["subnet"], strict=False)
        except ValueError:
            continue
        if parsed in network:
            matching_segments.append(segment)
    metadata["network_segments"] = matching_segments
    return metadata


@app.get("/api/v1/inventory/devices", tags=["inventory"])
def list_network_devices(
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
) -> list[dict[str, object]]:
    identities = _identity_index(datetime.now(UTC))
    segments = _network_segments()
    device_index = {
        (item["gateway_id"], item["mac_address"]): item["payload"]
        for item in store.list_gateway_devices()
    }
    result = []
    for item in store.list_inventory_observations(limit=limit):
        classified = _classify_ip(item["ip_address"])
        if classified is None:
            continue
        address, scope = classified
        metadata = _node_metadata(address, identities, segments, device_index)
        result.append({
            **metadata,
            "scope": scope,
            "protocols": sorted(item["protocols"]),
            "first_seen": item["first_seen"].isoformat(),
            "last_seen": item["last_seen"].isoformat(),
            "observations": item["observations"],
        })
    result.sort(key=lambda item: item["observations"], reverse=True)
    return result[:limit]


@app.get("/api/v1/inventory/topology", tags=["inventory"])
def get_network_topology(
    limit: Annotated[int, Query(ge=1, le=5000)] = 1000,
) -> dict[str, object]:
    identities = _identity_index(datetime.now(UTC))
    segments = _network_segments()
    device_index = {
        (item["gateway_id"], item["mac_address"]): item["payload"]
        for item in store.list_gateway_devices()
    }
    links: dict[tuple[str, str, str], dict[str, object]] = {}
    node_scopes: dict[str, str] = {}
    for item in store.list_topology_observations(limit=limit):
        source_ip = _classify_ip(item["source"])
        target_ip = _classify_ip(item["target"])
        if source_ip is None or target_ip is None:
            continue
        source, source_scope = source_ip
        target, target_scope = target_ip
        node_scopes[source] = source_scope
        node_scopes[target] = target_scope
        links[(source, target, item["protocol"])] = item

    edges = []
    for (source, target, protocol), item in links.items():
        source_scope = node_scopes[source]
        target_scope = node_scopes[target]
        if source_scope == "private" and target_scope == "public":
            direction = "outbound"
        elif source_scope == "public" and target_scope == "private":
            direction = "inbound"
        elif source_scope == target_scope == "private":
            direction = "internal"
        elif source_scope == target_scope == "public":
            direction = "external"
        else:
            direction = "other"
        edges.append({
            "source": source,
            "target": target,
            "protocol": protocol,
            "observations": item["observations"],
            "direction": direction,
            "relationship": "connection",
            "evidence_type": "observed",
            "confidence": "high",
            "source_integration_ids": item["source_integration_ids"],
            "source_event_types": item["source_event_types"],
            "first_seen": item["first_seen"].isoformat(),
            "last_seen": item["last_seen"].isoformat(),
        })

    for item in store.list_nat_observations(limit=limit):
        source_ip = _classify_ip(item["source"])
        target_ip = _classify_ip(item["target"])
        if source_ip is None or target_ip is None:
            continue
        source, source_scope = source_ip
        target, target_scope = target_ip
        node_scopes[source] = source_scope
        node_scopes[target] = target_scope
        edges.append({
            "source": source,
            "target": target,
            "protocol": item["protocol"],
            "observations": item["observations"],
            "direction": "translation",
            "relationship": "nat_translation",
            "evidence_type": "observed",
            "confidence": "high",
            "source_integration_ids": item["source_integration_ids"],
            "source_event_types": item["source_event_types"],
            "first_seen": item["first_seen"].isoformat(),
            "last_seen": item["last_seen"].isoformat(),
        })

    node_details = [
        _node_metadata(address, identities, segments, device_index)
        for address in sorted(node_scopes)
    ]
    relationships = []
    for detail in node_details:
        for segment in detail["network_segments"]:
            relationships.append({
                "source": detail["ip_address"],
                "target": segment["subnet"],
                "relationship": "network_segment_membership",
                "evidence_type": "inferred",
                "confidence": segment["confidence"],
                "source_integration_ids": [segment["gateway_id"]],
                "source_event_types": ["gateway.discovery"],
            })
    return {
        "nodes": sorted(node_scopes),
        "node_details": node_details,
        "edges": edges[:limit],
        "segments": segments,
        "relationships": relationships[:limit],
    }

@app.post("/api/v1/dns/{integration_id}/queries", status_code=202, tags=["privacy"])
def ingest_dns_queries(
    integration_id: str,
    records: Annotated[list[dict[str, Any]], Body()],
) -> dict[str, object]:
    integration = registry.get(integration_id)
    if integration is None or integration.kind not in {"pihole", "adguard"}:
        raise HTTPException(status_code=404, detail="DNS privacy integration not found")
    _require_enabled_ingestion(integration_id, integration.enabled, "dns_queries")
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


@app.post("/api/v1/privacy/sources/{integration_id}/sync", status_code=202, tags=["privacy"])
def sync_privacy_source(integration_id: str) -> dict[str, object]:
    integration = registry.get(integration_id)
    if integration is None or integration.kind not in {"pihole", "adguard"}:
        raise HTTPException(status_code=404, detail="DNS privacy integration not found")
    _require_enabled_ingestion(integration_id, integration.enabled, "dns_manual_sync")
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


@app.delete("/api/v1/privacy/sources/{integration_id}/cursor", tags=["privacy"])
def reset_privacy_source_cursor(integration_id: str) -> dict[str, str]:
    integration = registry.get(integration_id)
    if integration is None or integration.kind not in {"pihole", "adguard"}:
        raise HTTPException(status_code=404, detail="DNS privacy integration not found")
    store.delete_integration_poll_cursor(integration_id)
    reset_poll_status(integration_id)
    store.write_audit(
        "privacy.provider_poll.cursor_reset", None, integration_id,
        {"provider": integration.kind, "reason": "administrator_requested"},
    )
    return {"status": "reset", "integration_id": integration_id}


@app.get("/api/v1/privacy/sources", tags=["privacy"])
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


@app.get("/api/v1/privacy/analytics/domains", tags=["privacy"])
def privacy_domain_analytics(
    days: Annotated[int, Query(ge=1, le=365)] = 30,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[dict[str, object]]:
    return store.privacy_domain_stats(days, limit)


@app.get("/api/v1/privacy/analytics/devices", tags=["privacy"])
def privacy_device_analytics(
    days: Annotated[int, Query(ge=1, le=365)] = 30,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[dict[str, object]]:
    return store.privacy_client_stats(days, limit)


@app.get("/api/v1/privacy/trends", tags=["privacy"])
def privacy_trends(
    days: Annotated[int, Query(ge=1, le=365)] = 30,
) -> list[dict[str, object]]:
    return store.privacy_trends(days)


@app.get("/api/v1/privacy/report", tags=["privacy"])
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


@app.get("/api/v1/privacy/lists", tags=["privacy"])
def list_privacy_lists(integration_id: str | None = None) -> list[dict[str, object]]:
    return store.list_privacy_lists(integration_id)


@app.get("/api/v1/privacy/classifications/overrides", tags=["privacy"])
def list_classification_overrides() -> dict[str, dict[str, object]]:
    return store.list_privacy_classification_overrides()


@app.put("/api/v1/privacy/classifications/overrides/{domain}", tags=["privacy"])
def set_classification_override(
    domain: str, request: ClassificationOverrideRequest
) -> dict[str, object]:
    try:
        normalized = normalize_domain(domain)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    store.upsert_privacy_classification_override(normalized, request.action, request.reason)
    return store.list_privacy_classification_overrides()[normalized]


@app.delete("/api/v1/privacy/classifications/overrides/{domain}", tags=["privacy"])
def delete_classification_override(domain: str) -> Response:
    try:
        normalized = normalize_domain(domain)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if not store.delete_privacy_classification_override(normalized):
        raise HTTPException(status_code=404, detail="Classification override not found")
    return Response(status_code=204)


@app.post("/api/v1/privacy/lists", status_code=201, tags=["privacy"])
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


@app.post("/api/v1/privacy/lists/{integration_id}/sync", status_code=200, tags=["privacy"])
def sync_privacy_lists(integration_id: str) -> dict[str, object]:
    integration = registry.get(integration_id)
    if integration is None or integration.kind not in {"pihole", "adguard"}:
        raise HTTPException(status_code=404, detail="DNS privacy integration not found")
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


@app.delete("/api/v1/privacy/lists/{list_type}/{domain}", status_code=204, tags=["privacy"])
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


@app.get("/api/v1/reports/operations", tags=["reports"])
def operations_report(
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> dict[str, object]:
    """Bounded operational snapshot across gateways, integrations, incidents and response."""
    gateways = gateway_connections.list_status()
    integrations = registry.list_all()
    incidents = store.list_incidents(limit=limit)
    decisions = store.list_policy_decisions(limit=limit)
    executions = store.list_response_executions(limit=limit)
    audit = store.list_audit(limit)

    def count_by(items: list[dict[str, object]], key: str) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in items:
            value = item.get(key)
            label = str(value) if value is not None else "unknown"
            counts[label] = counts.get(label, 0) + 1
        return counts

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "sample_limit": limit,
        "gateways": {"total": len(gateways), "by_status": count_by(gateways, "status"), "items": gateways},
        "integrations": {
            "total": len(integrations),
            "enabled": sum(1 for item in integrations if item.enabled),
            "disabled": sum(1 for item in integrations if not item.enabled),
        },
        "incidents": {
            "sampled": len(incidents),
            "by_status": count_by(incidents, "status"),
            "open": sum(1 for item in incidents if item.get("status") == "open"),
        },
        "policy_decisions": {
            "sampled": len(decisions),
            "by_status": count_by(decisions, "status"),
            "pending_approval": sum(1 for item in decisions if item.get("status") == "pending_approval"),
        },
        "executions": {"sampled": len(executions), "by_status": count_by(executions, "status")},
        "audit": {"recent_records": len(audit), "limit": limit},
    }


@app.get("/api/v1/audit", tags=["audit"])
def list_audit_records(
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[dict[str, object]]:
    return store.list_audit(limit)
