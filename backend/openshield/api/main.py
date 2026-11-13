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
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field, SecretStr

from openshield.ai.orchestrator import investigate_incident
from openshield.ai.providers import AIProviderError, test_ollama, test_openai
from openshield.core.logging import configure_logging
from openshield.core.metrics import MetricsRegistry
from openshield.core.secrets import SecretConfigurationError, SecretStore
from openshield.core.storage import PostgresStore
from openshield.events.models import EventEnvelope
from openshield.gateway.models import GatewayConnectRequest, GatewayHeartbeatRequest
from openshield.gateway.registry import GatewayConnectionRegistry
from openshield.integrations.ai import AIProviderAdapter
from openshield.integrations.models import IntegrationRegistration, IntegrationUpdate
from openshield.integrations.openwrt import OpenWrtAdapter
from openshield.integrations.openwrt_rpc import OpenWrtRPCClient
from openshield.integrations.registry import IntegrationRegistry
from openshield.integrations.threat_intel import ThreatIntelAdapter
from openshield.privacy.adapter import DnsPrivacyAdapter
from openshield.privacy.dns import normalize_dns_batch, normalize_domain
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
from openshield.threat_intel.providers import (
    ThreatIntelProviderError,
    lookup_crowdsec,
    lookup_misp,
)
from openshield.visibility.adapter import NetworkSensorAdapter
from openshield.visibility.normalizers import normalize_sensor_batch

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
    task = asyncio.create_task(run_dns_polling_loop(registry, store, metrics, interval)) if interval else None
    try:
        yield
    finally:
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass


app = FastAPI(
    title="OpenShield Node API",
    version="0.1.0",
    description="Gateway-first network security and privacy intelligence node.",
    lifespan=_dns_polling_lifespan,
)


_AUTH_FAILURES: dict[str, tuple[float, int]] = {}
_AUTH_FAILURES_LOCK = threading.Lock()


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
        window, failures = _AUTH_FAILURES.get(remote, (now, 0))
        if now - window >= 60:
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
        with _AUTH_FAILURES_LOCK:
            window, failures = _AUTH_FAILURES.get(remote, (now, 0))
            if now - window >= 60:
                window, failures = now, 0
            _AUTH_FAILURES[remote] = (window, failures + 1)
        return JSONResponse(
            {"detail": "Authentication required"},
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="OpenShield", charset="UTF-8"'},
        )
    with _AUTH_FAILURES_LOCK:
        _AUTH_FAILURES.pop(remote, None)
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        origin = request.headers.get("origin")
        if origin:
            parsed = urlsplit(origin)
            if parsed.netloc != request.headers.get("host") or parsed.scheme not in {"http", "https"}:
                return JSONResponse({"detail": "Cross-origin state change rejected"}, status_code=403)
    return None


@app.middleware("http")
async def authenticate_requests(request: Request, call_next):
    path = request.url.path
    if path.startswith("/health/") or path == "/metrics":
        return await call_next(request)
    is_gateway = path.startswith("/api/v1/gateway/") or path == "/api/v1/events"
    if is_gateway:
        expected = os.getenv("OPENSHIELD_GATEWAY_TOKEN", "")
        if expected and not _gateway_token_valid(request):
            return JSONResponse({"detail": "Gateway authentication required"}, status_code=401)
        if _api_auth_enabled() and not expected:
            return JSONResponse({"detail": "OPENSHIELD_GATEWAY_TOKEN is required when API authentication is enabled"}, status_code=503)
        return await call_next(request)
    denied = _check_admin_auth(request)
    if denied is not None:
        return denied
    return await call_next(request)


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


store = PostgresStore(os.getenv("OPENSHIELD_DATABASE_URL", ""))
registry = IntegrationRegistry(store)
gateway_connections = GatewayConnectionRegistry(store)
metrics = MetricsRegistry()
adapters = {
    "openwrt": OpenWrtAdapter(),
    "suricata": NetworkSensorAdapter("suricata"),
    "zeek": NetworkSensorAdapter("zeek"),
    "pihole": DnsPrivacyAdapter("pihole"),
    "adguard": DnsPrivacyAdapter("adguard"),
    "crowdsec": ThreatIntelAdapter("crowdsec"),
    "misp": ThreatIntelAdapter("misp"),
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


class OpenWrtCredentials(BaseModel):
    base_url: str = Field(min_length=8, max_length=500)
    username: str = Field(min_length=1, max_length=128)
    password: SecretStr = Field(min_length=1, max_length=512)


class ThreatIntelCredentials(BaseModel):
    api_key: SecretStr = Field(min_length=8, max_length=2048)


class ThreatIntelEnrichRequest(BaseModel):
    event_ids: list[str] = Field(min_length=1, max_length=100)


class IncidentStatusRequest(BaseModel):
    status: Literal["open", "acknowledged", "closed", "false_positive"]
    reason: str = Field(default="", max_length=500)


class AIProviderCredentials(BaseModel):
    api_key: SecretStr = Field(min_length=8, max_length=2048)


class AIInvestigationRequest(BaseModel):
    provider_id: str = Field(min_length=2, max_length=64)


DASHBOARD_PATH = Path(__file__).resolve().parents[1] / "dashboard.html"


@app.get("/", response_class=FileResponse, include_in_schema=False)
def dashboard() -> FileResponse:
    if not DASHBOARD_PATH.is_file():
        raise HTTPException(status_code=404, detail="Dashboard asset not found")
    return FileResponse(DASHBOARD_PATH, media_type="text/html")


@app.get("/health/live", tags=["health"])
def liveness() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health/ready", tags=["health"])
def readiness() -> dict[str, str]:
    if not store.is_ready():
        raise HTTPException(status_code=503, detail="Database is not ready")
    return {"status": "ready"}


@app.post("/api/v1/integrations", status_code=201, tags=["integrations"])
def register_integration(registration: IntegrationRegistration) -> dict[str, object]:
    if registration.kind not in adapters:
        raise HTTPException(status_code=400, detail="Unsupported integration kind")
    try:
        item = registry.register(registration)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return item.model_dump(mode="json")


@app.get("/api/v1/integrations", tags=["integrations"])
def list_integrations() -> list[dict[str, object]]:
    return [item.model_dump(mode="json") for item in registry.list_all()]


@app.patch("/api/v1/integrations/{integration_id}", tags=["integrations"])
def update_integration(
    integration_id: str, changes: IntegrationUpdate
) -> dict[str, object]:
    if not changes.model_fields_set:
        raise HTTPException(status_code=422, detail="At least one field must be provided")
    item = registry.update(integration_id, changes)
    if item is None:
        raise HTTPException(status_code=404, detail="Integration not found")
    return item.model_dump(mode="json")


@app.delete(
    "/api/v1/integrations/{integration_id}",
    status_code=204,
    response_class=Response,
    tags=["integrations"],
)
def delete_integration(integration_id: str) -> Response:
    if not registry.delete(integration_id):
        raise HTTPException(status_code=404, detail="Integration not found")
    return Response(status_code=204)


@app.get("/api/v1/integrations/{integration_id}/probe", tags=["integrations"])
def probe_integration(integration_id: str) -> dict[str, object]:
    item = registry.get(integration_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Integration not found")
    result = adapters[item.kind].probe(item)
    if item.kind in {"crowdsec", "misp"}:
        result["credentials_configured"] = store.get_integration_secret(integration_id) is not None
    if item.kind == "openai":
        result["credentials_configured"] = store.get_integration_secret(integration_id) is not None
    return result



@app.post("/api/v1/integrations/{integration_id}/test", tags=["integrations"])
def test_integration_connection(integration_id: str) -> dict[str, object]:
    """Test a DNS provider connection without persisting or importing query records."""
    item = registry.get(integration_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Integration not found")
    if not item.enabled:
        raise HTTPException(status_code=409, detail="Integration is disabled")
    if item.kind in {"pihole", "adguard"}:
        try:
            records = fetch_dns_records(item)
        except DnsProviderError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        return {
            "status": "connected",
            "integration_id": integration_id,
            "provider": item.kind,
            "records_available": len(records),
            "imported": 0,
        }
    if item.kind in {"crowdsec", "misp"}:
        try:
            secret = SecretStore(store).get(integration_id)
        except SecretConfigurationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        if not secret or not isinstance(secret.get("api_key"), str):
            raise HTTPException(status_code=409, detail="Threat intelligence API key is not configured")
        try:
            if item.kind == "crowdsec":
                result = lookup_crowdsec("8.8.8.8", secret["api_key"])
                matches = int(bool(result.get("matched")))
            else:
                base_url = item.config.get("base_url")
                if not isinstance(base_url, str):
                    raise HTTPException(status_code=422, detail="MISP base URL is not configured")
                result = lookup_misp(base_url, secret["api_key"], "ip", "192.0.2.1")
                matches = len(result.get("attributes", []))
        except ThreatIntelProviderError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        return {
            "status": "connected",
            "integration_id": integration_id,
            "provider": item.kind,
            "matches": matches,
            "message": "Provider authentication and API request succeeded.",
        }
    if item.kind == "ollama":
        base_url = item.config.get("base_url", "http://localhost:11434")
        if not isinstance(base_url, str):
            raise HTTPException(status_code=422, detail="Ollama base URL is invalid")
        try:
            models = test_ollama(base_url)
        except (AIProviderError, ValueError) as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        configured_model = item.config.get("model")
        if not isinstance(configured_model, str) or configured_model not in models:
            raise HTTPException(status_code=409, detail="Configured Ollama model is not installed")
        return {
            "status": "connected", "integration_id": integration_id,
            "provider": "ollama", "models": models, "model_available": True,
        }
    if item.kind == "openai":
        if os.getenv("OPENSHIELD_CLOUD_AI_ENABLED", "false").lower() not in {"1", "true", "yes"}:
            raise HTTPException(status_code=409, detail="Cloud AI is globally disabled")
        if item.config.get("cloud_enabled") is not True:
            raise HTTPException(status_code=409, detail="Cloud AI is not explicitly enabled for this integration")
        try:
            secret = SecretStore(store).get(integration_id)
        except SecretConfigurationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        api_key = secret.get("api_key") if secret else None
        if not isinstance(api_key, str) or not api_key:
            raise HTTPException(status_code=409, detail="OpenAI API key is not configured")
        try:
            models = test_openai(api_key)
        except AIProviderError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        configured_model = item.config.get("model")
        if not isinstance(configured_model, str) or configured_model not in models:
            raise HTTPException(status_code=409, detail="Configured OpenAI model is not available to this API key")
        return {
            "status": "connected", "integration_id": integration_id,
            "provider": "openai", "models_available": len(models), "model_available": True,
        }
    if item.kind in {"suricata", "zeek"}:
        return {
            "status": "configured",
            "integration_id": integration_id,
            "mode": "push",
            "ingestion_endpoint": f"/api/v1/sensors/{integration_id}/events",
        }
    raise HTTPException(status_code=400, detail="Connection test is not supported for this integration kind")

@app.put("/api/v1/integrations/{integration_id}/ai-credentials", tags=["integrations"])
def save_ai_credentials(
    integration_id: str, credentials: AIProviderCredentials
) -> dict[str, object]:
    integration = registry.get(integration_id)
    if integration is None or integration.kind != "openai":
        raise HTTPException(status_code=404, detail="OpenAI integration not found")
    if os.getenv("OPENSHIELD_CLOUD_AI_ENABLED", "false").lower() not in {"1", "true", "yes"}:
        raise HTTPException(status_code=409, detail="Cloud AI is globally disabled")
    if not os.getenv("OPENSHIELD_SECRET_KEY"):
        raise HTTPException(status_code=503, detail="OPENSHIELD_SECRET_KEY is required for provider credentials")
    if integration.config.get("cloud_enabled") is not True:
        raise HTTPException(status_code=409, detail="Explicitly enable cloud use for this integration before storing its API key")
    try:
        SecretStore(store).set(
            integration_id, {"api_key": credentials.api_key.get_secret_value()},
        )
    except SecretConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {
        "status": "saved", "integration_id": integration_id,
        "credentials_configured": True, "secret_storage": "encrypted",
    }


@app.delete("/api/v1/integrations/{integration_id}/ai-credentials", status_code=204, tags=["integrations"])
def delete_ai_credentials(integration_id: str) -> Response:
    integration = registry.get(integration_id)
    if integration is None or integration.kind != "openai":
        raise HTTPException(status_code=404, detail="OpenAI integration not found")
    store.delete_integration_secret(integration_id)
    return Response(status_code=204)


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


@app.put("/api/v1/integrations/{integration_id}/threat-intel-credentials", tags=["integrations"])
def save_threat_intel_credentials(
    integration_id: str, credentials: ThreatIntelCredentials
) -> dict[str, object]:
    integration = registry.get(integration_id)
    if integration is None or integration.kind not in {"crowdsec", "misp"}:
        raise HTTPException(status_code=404, detail="Threat intelligence integration not found")
    if not os.getenv("OPENSHIELD_SECRET_KEY"):
        raise HTTPException(status_code=503, detail="OPENSHIELD_SECRET_KEY is required for provider credentials")
    if integration.kind == "misp":
        base_url = integration.config.get("base_url")
        if not isinstance(base_url, str):
            raise HTTPException(status_code=422, detail="MISP integration requires config.base_url")
        parsed = urlsplit(base_url)
        if (
            parsed.scheme not in {"http", "https"} or not parsed.netloc
            or parsed.username or parsed.password or parsed.query or parsed.fragment
        ):
            raise HTTPException(status_code=422, detail="MISP base URL must be an absolute HTTP(S) URL without credentials")
    try:
        SecretStore(store).set(
            integration_id, {"api_key": credentials.api_key.get_secret_value()},
        )
    except SecretConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {
        "status": "saved", "integration_id": integration_id,
        "credentials_configured": True, "secret_storage": "encrypted",
    }


@app.delete("/api/v1/integrations/{integration_id}/threat-intel-credentials", status_code=204, tags=["integrations"])
def delete_threat_intel_credentials(integration_id: str) -> Response:
    integration = registry.get(integration_id)
    if integration is None or integration.kind not in {"crowdsec", "misp"}:
        raise HTTPException(status_code=404, detail="Threat intelligence integration not found")
    store.delete_integration_secret(integration_id)
    return Response(status_code=204)


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


@app.put("/api/v1/integrations/{integration_id}/openwrt-credentials", tags=["integrations"])
def save_openwrt_credentials(
    integration_id: str, credentials: OpenWrtCredentials
) -> dict[str, object]:
    integration = registry.get(integration_id)
    if integration is None or integration.kind != "openwrt":
        raise HTTPException(status_code=404, detail="OpenWrt integration not found")
    if not os.getenv("OPENSHIELD_GATEWAY_TOKEN"):
        raise HTTPException(
            status_code=503,
            detail="Configure OPENSHIELD_GATEWAY_TOKEN on Node and connector before storing router credentials",
        )
    try:
        parsed = urlsplit(credentials.base_url)
        if (
            parsed.scheme not in {"http", "https"} or not parsed.netloc
            or parsed.username or parsed.password or parsed.query or parsed.fragment
        ):
            raise ValueError("OpenWrt URL must be an absolute HTTP(S) URL without credentials")
        OpenWrtRPCClient(credentials.base_url, credentials.username, credentials.password)
        SecretStore(store).set(integration_id, {
            "base_url": credentials.base_url,
            "username": credentials.username,
            "password": credentials.password.get_secret_value(),
        })
    except SecretConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    registry.update(
        integration_id,
        IntegrationUpdate(config={
            **integration.config,
            "base_url": credentials.base_url.rstrip("/"),
            "rpc_configured": True,
        }),
    )
    return {
        "status": "saved",
        "integration_id": integration_id,
        "credentials_configured": True,
        "secret_storage": "encrypted",
        "message": "Credentials are encrypted at rest and delivered only to the authenticated gateway connector.",
    }


@app.delete("/api/v1/integrations/{integration_id}/openwrt-credentials", tags=["integrations"])
def delete_openwrt_credentials(integration_id: str) -> Response:
    integration = registry.get(integration_id)
    if integration is None or integration.kind != "openwrt":
        raise HTTPException(status_code=404, detail="OpenWrt integration not found")
    store.delete_integration_secret(integration_id)
    registry.update(
        integration_id,
        IntegrationUpdate(config={
            **integration.config,
            "rpc_configured": False,
        }),
    )
    return Response(status_code=204)


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
    if health_events:
        health = health_events[0]
        if health.payload.get("status") == "reachable":
            return {
                "status": "router_rpc_connected",
                "message": "Gateway Connector and OpenWrt RPC are responding.",
                "last_rpc_check": health.observed_at.isoformat(),
                "gateway": gateway,
            }
        if health.payload.get("status") == "unavailable":
            return {
                "status": "router_rpc_failed",
                "message": "Gateway Connector is online but OpenWrt RPC failed. Check router URL, RPC credentials, ACL permissions and TLS trust.",
                "last_rpc_check": health.observed_at.isoformat(),
                "gateway": gateway,
            }
    return {
        "status": "connector_connected",
        "message": "Gateway Connector is online. Waiting for its next OpenWrt RPC health check.",
        "gateway": gateway,
    }


@app.get("/api/v1/gateway/config/{gateway_id}", tags=["gateway"])
def gateway_configuration(gateway_id: str, request: Request) -> dict[str, object]:
    if not _gateway_token_valid(request):
        raise HTTPException(status_code=401, detail="Gateway authentication required")
    integration = registry.get(gateway_id)
    if integration is None or integration.kind != "openwrt":
        raise HTTPException(status_code=404, detail="Gateway integration not found")
    try:
        credentials = SecretStore(store).get(gateway_id)
    except SecretConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {"gateway_id": gateway_id, "openwrt_config": credentials}


@app.post("/api/v1/gateway/connect", status_code=201, tags=["gateway"])
def connect_gateway(request: GatewayConnectRequest, http_request: Request) -> dict[str, object]:
    # Residential mode: first connection provisions the local gateway integration.
    integration = registry.get(request.gateway_id)
    if integration is None:
        try:
            registry.register(
                IntegrationRegistration(
                    integration_id=request.gateway_id,
                    kind=request.gateway_type,
                    display_name="Home gateway",
                )
            )
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
    elif integration.kind != request.gateway_type:
        raise HTTPException(status_code=409, detail="Gateway integration kind mismatch")

    encrypted_secret = store.get_integration_secret(request.gateway_id)
    if encrypted_secret and not _gateway_token_valid(http_request):
        raise HTTPException(status_code=401, detail="Gateway authentication required to receive router credentials")
    connection = gateway_connections.connect(request)
    metrics.increment("openshield_gateway_connections_total")
    try:
        openwrt_config = SecretStore(store).get(connection.gateway_id) if encrypted_secret else None
    except SecretConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {
        "status": "connected",
        "gateway_id": connection.gateway_id,
        "protocol_version": connection.protocol_version,
        "accepted_capabilities": [item.value for item in connection.capabilities],
        "connected_at": connection.connected_at.isoformat(),
        "openwrt_config": openwrt_config,
    }


@app.post("/api/v1/gateway/heartbeat", tags=["gateway"])
def gateway_heartbeat(request: GatewayHeartbeatRequest, http_request: Request) -> dict[str, object]:
    connection = gateway_connections.heartbeat(request.gateway_id)
    if connection is None:
        raise HTTPException(status_code=409, detail="Gateway must connect before sending heartbeat")
    encrypted_secret = store.get_integration_secret(connection.gateway_id)
    if encrypted_secret and not _gateway_token_valid(http_request):
        raise HTTPException(status_code=401, detail="Gateway authentication required to receive router credentials")
    metrics.increment("openshield_gateway_heartbeats_total")
    try:
        openwrt_config = SecretStore(store).get(connection.gateway_id) if encrypted_secret else None
    except SecretConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {
        "status": "acknowledged",
        "gateway_id": connection.gateway_id,
        "last_seen_at": connection.last_seen_at.isoformat(),
        "openwrt_config": openwrt_config,
    }


@app.get("/api/v1/gateways", tags=["gateway"])
def list_gateways() -> list[dict[str, object]]:
    return gateway_connections.list_status()


@app.get("/api/v1/gateways/{gateway_id}", tags=["gateway"])
def get_gateway_status(gateway_id: str) -> dict[str, object]:
    gateway = gateway_connections.get_status(gateway_id)
    if gateway is None:
        raise HTTPException(status_code=404, detail="Gateway not found")
    return gateway


@app.post("/api/v1/events", status_code=202, tags=["events"])
def ingest_event(event: EventEnvelope, request: Request) -> dict[str, str]:
    if (
        event.source.kind == "openwrt"
        and store.get_integration_secret(event.source.integration_id)
        and not _gateway_token_valid(request)
    ):
        raise HTTPException(status_code=401, detail="Gateway authentication required")
    integration = registry.get(event.source.integration_id)
    if integration is None:
        raise HTTPException(status_code=400, detail="Unknown source integration")
    if integration.kind != event.source.kind:
        raise HTTPException(status_code=400, detail="Event source kind does not match integration")
    inserted = store.insert_event(event)
    if inserted:
        metrics.increment("openshield_events_ingested_total")
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
    request: Request,
    records: Annotated[list[dict[str, Any]], Body()],
) -> dict[str, object]:
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Sensor batch body exceeds 5 MiB")
    integration = registry.get(integration_id)
    if integration is None or integration.kind not in {"suricata", "zeek"} or not integration.enabled:
        raise HTTPException(status_code=404, detail="Network sensor integration not found")
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


@app.get("/api/v1/inventory/devices", tags=["inventory"])
def list_network_devices(
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
) -> list[dict[str, object]]:
    result = []
    for item in store.list_inventory_observations():
        classified = _classify_ip(item["ip_address"])
        if classified is None:
            continue
        address, scope = classified
        result.append({
            "ip_address": address,
            "ip_version": ipaddress.ip_address(address).version,
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
    links: dict[tuple[str, str, str], int] = {}
    node_scopes: dict[str, str] = {}
    for item in store.list_topology_observations():
        source_ip = _classify_ip(item["source"])
        target_ip = _classify_ip(item["target"])
        if source_ip is None or target_ip is None:
            continue
        source, source_scope = source_ip
        target, target_scope = target_ip
        node_scopes[source] = source_scope
        node_scopes[target] = target_scope
        links[(source, target, item["protocol"])] = item["observations"]

    edges = []
    for (source, target, protocol), count in list(links.items())[:limit]:
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
            "source": source, "target": target, "protocol": protocol,
            "observations": count, "direction": direction,
        })
    nodes = sorted(node_scopes)
    node_details = [
        {"ip_address": address, "scope": node_scopes[address],
         "ip_version": ipaddress.ip_address(address).version}
        for address in nodes
    ]
    return {"nodes": nodes, "node_details": node_details, "edges": edges}


@app.post("/api/v1/dns/{integration_id}/queries", status_code=202, tags=["privacy"])
def ingest_dns_queries(
    integration_id: str,
    request: Request,
    records: Annotated[list[dict[str, Any]], Body()],
) -> dict[str, object]:
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="DNS batch body exceeds 5 MiB")
    integration = registry.get(integration_id)
    if integration is None or integration.kind not in {"pihole", "adguard"}:
        raise HTTPException(status_code=404, detail="DNS privacy integration not found")
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
    if not integration.enabled:
        raise HTTPException(status_code=409, detail="DNS privacy integration is disabled")
    _record_poll_attempt(integration_id)
    try:
        records = fetch_dns_records(integration)
        events = normalize_dns_batch(
            integration.kind, integration_id, records,
            store.list_privacy_classification_overrides(),
        ) if records else []
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
            "last_imported": poll.get("last_imported", 0),
            "last_duplicates": poll.get("last_duplicates", 0),
            "last_error": poll.get("last_error"),
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
    entries = store.list_privacy_lists("openshield-local")
    try:
        result = sync_provider_lists(integration, entries)
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


@app.get("/api/v1/audit", tags=["audit"])
def list_audit_records(
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[dict[str, object]]:
    return store.list_audit(limit)


@app.get("/metrics", response_class=PlainTextResponse, tags=["metrics"], include_in_schema=False)
def prometheus_metrics() -> PlainTextResponse:
    return PlainTextResponse(metrics.render(), media_type="text/plain; version=0.0.4")
