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

from openshield.core.logging import configure_logging
from openshield.core.metrics import MetricsRegistry
from openshield.core.secrets import SecretConfigurationError, SecretStore
from openshield.core.storage import PostgresStore
from openshield.events.models import EventEnvelope
from openshield.gateway.models import GatewayConnectRequest, GatewayHeartbeatRequest
from openshield.gateway.registry import GatewayConnectionRegistry
from openshield.integrations.crowdsec import CrowdSecAdapter, CrowdSecClient, CrowdSecError
from openshield.integrations.grafana import GrafanaAdapter, GrafanaClient, GrafanaError
from openshield.integrations.misp import MispAdapter, MispClient, MispError
from openshield.integrations.models import IntegrationRegistration, IntegrationUpdate
from openshield.integrations.openwrt import OpenWrtAdapter
from openshield.integrations.openwrt_rpc import OpenWrtRPCClient
from openshield.integrations.opnsense import OPNsenseAdapter, OPNsenseClient, OPNsenseError
from openshield.integrations.pfsense import PfSenseAdapter, PfSenseClient, PfSenseError
from openshield.integrations.prometheus import PrometheusAdapter, PrometheusClient, PrometheusError
from openshield.integrations.registry import IntegrationRegistry
from openshield.integrations.wazuh import WazuhAdapter, WazuhClient, WazuhError
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
    is_gateway = path.startswith("/api/v1/gateway/") or path == "/api/v1/events"
    if is_gateway:
        expected = os.getenv("OPENSHIELD_GATEWAY_TOKEN", "")
        if expected and not _gateway_token_valid(request):
            return JSONResponse({"detail": "Gateway authentication required"}, status_code=401)
        if _api_auth_enabled() and not expected:
            return JSONResponse({"detail": "OPENSHIELD_GATEWAY_TOKEN is required when API authentication is enabled"}, status_code=503)
        response = await call_next(request)
    else:
        denied = _check_admin_auth(request)
        if denied is not None:
            return denied
        response = await call_next(request)
    if path.startswith("/api/v1/gateway/") or path.endswith((
        "/openwrt-credentials", "/opnsense-credentials", "/pfsense-credentials",
        "/opnsense-diagnostics", "/pfsense-diagnostics",
        "/crowdsec-credentials", "/crowdsec-diagnostics",
        "/misp-credentials", "/misp-diagnostics",
        "/wazuh-credentials", "/wazuh-diagnostics",
        "/prometheus-credentials", "/prometheus-diagnostics",
        "/grafana-credentials", "/grafana-diagnostics",
    )):
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


store = PostgresStore(os.getenv("OPENSHIELD_DATABASE_URL", ""))
registry = IntegrationRegistry(store)
gateway_connections = GatewayConnectionRegistry(store)
metrics = MetricsRegistry()
adapters = {
    "openwrt": OpenWrtAdapter(),
    "opnsense": OPNsenseAdapter(),
    "pfsense": PfSenseAdapter(),
    "crowdsec": CrowdSecAdapter(),
    "misp": MispAdapter(),
    "wazuh": WazuhAdapter(),
    "prometheus": PrometheusAdapter(),
    "grafana": GrafanaAdapter(),
    "suricata": NetworkSensorAdapter("suricata"),
    "zeek": NetworkSensorAdapter("zeek"),
    "pihole": DnsPrivacyAdapter("pihole"),
    "adguard": DnsPrivacyAdapter("adguard"),
}


class PrivacyListEntry(BaseModel):
    list_type: str = Field(pattern=r"^(allow|block)$")
    domain: str = Field(min_length=3, max_length=253)
    comment: str = Field(default="", max_length=500)


class ClassificationOverrideRequest(BaseModel):
    action: Literal["allow", "tracker"]
    reason: str = Field(default="", max_length=500)


class OPNsenseCredentials(BaseModel):
    base_url: str = Field(min_length=8, max_length=500)
    api_key: str = Field(min_length=1, max_length=512)
    api_secret: SecretStr = Field(min_length=1, max_length=1024)


class PfSenseCredentials(BaseModel):
    base_url: str = Field(min_length=8, max_length=500)
    api_key: SecretStr = Field(min_length=1, max_length=1024)


class CrowdSecCredentials(BaseModel):
    base_url: str = Field(min_length=8, max_length=500)
    bouncer_api_key: SecretStr = Field(min_length=1, max_length=1024)
    machine_id: str | None = Field(default=None, max_length=128)
    machine_password: SecretStr | None = Field(default=None, max_length=1024)


class MispCredentials(BaseModel):
    base_url: str = Field(min_length=8, max_length=500)
    api_key: SecretStr = Field(min_length=1, max_length=1024)


class WazuhCredentials(BaseModel):
    base_url: str = Field(min_length=8, max_length=500)
    username: SecretStr = Field(min_length=1, max_length=256)
    password: SecretStr = Field(min_length=1, max_length=1024)


class PrometheusCredentials(BaseModel):
    base_url: str = Field(min_length=8, max_length=500)
    bearer_token: SecretStr | None = Field(default=None, min_length=1, max_length=4096)


class GrafanaCredentials(BaseModel):
    base_url: str = Field(min_length=8, max_length=500)
    bearer_token: SecretStr | None = Field(default=None, min_length=1, max_length=4096)


class OpenWrtCredentials(BaseModel):
    base_url: str = Field(min_length=8, max_length=500)
    username: str = Field(min_length=1, max_length=128)
    password: SecretStr = Field(min_length=1, max_length=512)


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
    return adapters[item.kind].probe(item)



@app.post("/api/v1/integrations/{integration_id}/test", tags=["integrations"])
def test_integration_connection(integration_id: str) -> dict[str, object]:
    """Test a DNS provider connection without persisting or importing query records."""
    item = registry.get(integration_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Integration not found")
    if not item.enabled:
        raise HTTPException(status_code=409, detail="Integration is disabled")
    if item.kind == "opnsense":
        credentials = SecretStore(store).get(integration_id)
        if credentials is None:
            raise HTTPException(status_code=409, detail="OPNsense credentials are not configured")
        try:
            client = OPNsenseClient(
                str(credentials["base_url"]), str(credentials["api_key"]),
                str(credentials["api_secret"]),
            )
            system = client.get("/api/diagnostics/system/system_information")
        except (KeyError, TypeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail="Stored OPNsense credentials are invalid") from exc
        except OPNsenseError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        return {"status": "connected", "integration_id": integration_id, "provider": "opnsense",
                "system_information_available": bool(system), "imported": 0}
    if item.kind == "pfsense":
        credentials = SecretStore(store).get(integration_id)
        if credentials is None:
            raise HTTPException(status_code=409, detail="pfSense API key is not configured")
        try:
            client = PfSenseClient(str(credentials["base_url"]), str(credentials["api_key"]))
            system = client.get("/api/v2/status/system")
        except (KeyError, TypeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail="Stored pfSense credentials are invalid") from exc
        except PfSenseError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        return {
            "status": "connected", "integration_id": integration_id, "provider": "pfsense",
            "system_information_available": bool(system), "imported": 0,
        }
    if item.kind == "crowdsec":
        try:
            credentials = SecretStore(store).get(integration_id)
            if credentials is None:
                raise HTTPException(status_code=409, detail="CrowdSec credentials are not configured")
            diagnostics = CrowdSecClient(
                str(credentials["base_url"]),
                str(credentials["bouncer_api_key"]),
                str(credentials.get("machine_id") or "") or None,
                str(credentials.get("machine_password") or "") or None,
            ).diagnostics()
        except SecretConfigurationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail="Stored CrowdSec credentials are invalid") from exc
        except CrowdSecError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        summary = diagnostics["summary"]
        return {
            "status": "connected",
            "integration_id": integration_id,
            "provider": "crowdsec",
            "alerts_available": summary["alerts_available"],
            "decisions_available": summary["decisions_available"],
            "imported": 0,
        }
    if item.kind == "wazuh":
        try:
            credentials = SecretStore(store).get(integration_id)
            if credentials is None:
                raise HTTPException(status_code=409, detail="Wazuh credentials are not configured")
            diagnostics = WazuhClient(
                str(credentials["base_url"]),
                str(credentials["username"]),
                str(credentials["password"]),
            ).diagnostics()
        except SecretConfigurationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=422, detail="Stored Wazuh credentials are invalid"
            ) from exc
        except WazuhError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        return {
            "status": "connected",
            "integration_id": integration_id,
            "provider": "wazuh",
            "agents_available": diagnostics["summary"]["agents_available"],
            "imported": 0,
        }
    if item.kind == "prometheus":
        try:
            credentials = SecretStore(store).get(integration_id)
            if credentials is None:
                raise HTTPException(status_code=409, detail="Prometheus configuration is not saved")
            diagnostics = PrometheusClient(
                str(credentials["base_url"]), str(credentials.get("bearer_token") or "") or None
            ).diagnostics()
        except SecretConfigurationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail="Stored Prometheus configuration is invalid") from exc
        except PrometheusError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        return {"status": "connected", "integration_id": integration_id, "provider": "prometheus",
                "targets_available": diagnostics["summary"]["targets_available"], "imported": 0}
    if item.kind == "grafana":
        try:
            credentials = SecretStore(store).get(integration_id)
            if credentials is None:
                raise HTTPException(status_code=409, detail="Grafana configuration is not saved")
            diagnostics = GrafanaClient(
                str(credentials["base_url"]),
                str(credentials.get("bearer_token") or "") or None,
            ).diagnostics()
        except SecretConfigurationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=422, detail="Stored Grafana configuration is invalid"
            ) from exc
        except GrafanaError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        return {
            "status": "connected",
            "integration_id": integration_id,
            "provider": "grafana",
            "dashboards_returned": diagnostics["summary"]["dashboards_returned"],
            "imported": 0,
        }
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
    if item.kind in {"suricata", "zeek"}:
        return {
            "status": "configured",
            "integration_id": integration_id,
            "mode": "push",
            "ingestion_endpoint": f"/api/v1/sensors/{integration_id}/events",
        }
    raise HTTPException(status_code=400, detail="Connection test is not supported for this integration kind")

@app.put("/api/v1/integrations/{integration_id}/opnsense-credentials", tags=["integrations"])
def save_opnsense_credentials(
    integration_id: str, credentials: OPNsenseCredentials
) -> dict[str, object]:
    integration = registry.get(integration_id)
    if integration is None or integration.kind != "opnsense":
        raise HTTPException(status_code=404, detail="OPNsense integration not found")
    try:
        OPNsenseClient(
            credentials.base_url, credentials.api_key, credentials.api_secret.get_secret_value()
        )
        SecretStore(store).set(integration_id, {
            "base_url": credentials.base_url.rstrip("/"),
            "api_key": credentials.api_key,
            "api_secret": credentials.api_secret.get_secret_value(),
        })
    except SecretConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    registry.update(integration_id, IntegrationUpdate(config={
        **integration.config, "base_url": credentials.base_url.rstrip("/"),
        "auth_configured": True,
    }))
    return {"status": "saved", "integration_id": integration_id, "secret_storage": "encrypted"}


@app.delete("/api/v1/integrations/{integration_id}/opnsense-credentials", tags=["integrations"])
def delete_opnsense_credentials(integration_id: str) -> Response:
    integration = registry.get(integration_id)
    if integration is None or integration.kind != "opnsense":
        raise HTTPException(status_code=404, detail="OPNsense integration not found")
    SecretStore(store).delete(integration_id)
    registry.update(integration_id, IntegrationUpdate(config={
        **integration.config, "auth_configured": False,
    }))
    return Response(status_code=204)


@app.get("/api/v1/integrations/{integration_id}/opnsense-diagnostics", tags=["integrations"])
def opnsense_diagnostics(integration_id: str) -> dict[str, object]:
    integration = registry.get(integration_id)
    if integration is None or integration.kind != "opnsense":
        raise HTTPException(status_code=404, detail="OPNsense integration not found")
    try:
        credentials = SecretStore(store).get(integration_id)
        if credentials is None:
            raise HTTPException(status_code=409, detail="OPNsense credentials are not configured")
        client = OPNsenseClient(
            str(credentials["base_url"]), str(credentials["api_key"]),
            str(credentials["api_secret"]),
        )
        return {"status": "connected", "integration_id": integration_id, **client.diagnostics()}
    except SecretConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="Stored OPNsense credentials are invalid") from exc
    except OPNsenseError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.put("/api/v1/integrations/{integration_id}/pfsense-credentials", tags=["integrations"])
def save_pfsense_credentials(
    integration_id: str, credentials: PfSenseCredentials
) -> dict[str, object]:
    integration = registry.get(integration_id)
    if integration is None or integration.kind != "pfsense":
        raise HTTPException(status_code=404, detail="pfSense integration not found")
    try:
        PfSenseClient(credentials.base_url, credentials.api_key.get_secret_value())
        SecretStore(store).set(integration_id, {
            "base_url": credentials.base_url.rstrip("/"),
            "api_key": credentials.api_key.get_secret_value(),
        })
    except SecretConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    registry.update(integration_id, IntegrationUpdate(config={
        **integration.config, "base_url": credentials.base_url.rstrip("/"),
        "auth_configured": True,
    }))
    return {"status": "saved", "integration_id": integration_id, "secret_storage": "encrypted"}


@app.delete("/api/v1/integrations/{integration_id}/pfsense-credentials", tags=["integrations"])
def delete_pfsense_credentials(integration_id: str) -> Response:
    integration = registry.get(integration_id)
    if integration is None or integration.kind != "pfsense":
        raise HTTPException(status_code=404, detail="pfSense integration not found")
    SecretStore(store).delete(integration_id)
    registry.update(integration_id, IntegrationUpdate(config={
        **integration.config, "auth_configured": False,
    }))
    return Response(status_code=204)


@app.get("/api/v1/integrations/{integration_id}/pfsense-diagnostics", tags=["integrations"])
def pfsense_diagnostics(integration_id: str) -> dict[str, object]:
    integration = registry.get(integration_id)
    if integration is None or integration.kind != "pfsense":
        raise HTTPException(status_code=404, detail="pfSense integration not found")
    try:
        credentials = SecretStore(store).get(integration_id)
        if credentials is None:
            raise HTTPException(status_code=409, detail="pfSense API key is not configured")
        client = PfSenseClient(str(credentials["base_url"]), str(credentials["api_key"]))
        return {"status": "connected", "integration_id": integration_id, **client.diagnostics()}
    except SecretConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="Stored pfSense credentials are invalid") from exc
    except PfSenseError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.put("/api/v1/integrations/{integration_id}/crowdsec-credentials", tags=["integrations"])
def save_crowdsec_credentials(
    integration_id: str, credentials: CrowdSecCredentials
) -> dict[str, object]:
    integration = registry.get(integration_id)
    if integration is None or integration.kind != "crowdsec":
        raise HTTPException(status_code=404, detail="CrowdSec integration not found")
    machine_id = credentials.machine_id.strip() if credentials.machine_id else ""
    machine_password = (
        credentials.machine_password.get_secret_value()
        if credentials.machine_password is not None else ""
    )
    if bool(machine_id) != bool(machine_password):
        raise HTTPException(
            status_code=422,
            detail="CrowdSec machine ID and password must be supplied together",
        )
    try:
        CrowdSecClient(
            credentials.base_url,
            credentials.bouncer_api_key.get_secret_value(),
            machine_id or None,
            machine_password or None,
        )
        SecretStore(store).set(integration_id, {
            "base_url": credentials.base_url.rstrip("/"),
            "bouncer_api_key": credentials.bouncer_api_key.get_secret_value(),
            "machine_id": machine_id or None,
            "machine_password": machine_password or None,
        })
    except SecretConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    registry.update(integration_id, IntegrationUpdate(config={
        **integration.config,
        "base_url": credentials.base_url.rstrip("/"),
        "auth_configured": True,
        "alerts_auth_configured": bool(machine_id),
    }))
    return {
        "status": "saved",
        "integration_id": integration_id,
        "secret_storage": "encrypted",
        "alerts_auth_configured": bool(machine_id),
    }


@app.delete("/api/v1/integrations/{integration_id}/crowdsec-credentials", tags=["integrations"])
def delete_crowdsec_credentials(integration_id: str) -> Response:
    integration = registry.get(integration_id)
    if integration is None or integration.kind != "crowdsec":
        raise HTTPException(status_code=404, detail="CrowdSec integration not found")
    SecretStore(store).delete(integration_id)
    registry.update(integration_id, IntegrationUpdate(config={
        **integration.config,
        "auth_configured": False,
        "alerts_auth_configured": False,
    }))
    return Response(status_code=204)


@app.get("/api/v1/integrations/{integration_id}/crowdsec-diagnostics", tags=["integrations"])
def crowdsec_diagnostics(integration_id: str) -> dict[str, object]:
    integration = registry.get(integration_id)
    if integration is None or integration.kind != "crowdsec":
        raise HTTPException(status_code=404, detail="CrowdSec integration not found")
    try:
        credentials = SecretStore(store).get(integration_id)
        if credentials is None:
            raise HTTPException(status_code=409, detail="CrowdSec credentials are not configured")
        client = CrowdSecClient(
            str(credentials["base_url"]),
            str(credentials["bouncer_api_key"]),
            str(credentials.get("machine_id") or "") or None,
            str(credentials.get("machine_password") or "") or None,
        )
        return {
            "status": "connected",
            "integration_id": integration_id,
            **client.diagnostics(),
        }
    except SecretConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="Stored CrowdSec credentials are invalid") from exc
    except CrowdSecError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.put("/api/v1/integrations/{integration_id}/misp-credentials", tags=["integrations"])
def save_misp_credentials(
    integration_id: str, credentials: MispCredentials
) -> dict[str, object]:
    integration = registry.get(integration_id)
    if integration is None or integration.kind != "misp":
        raise HTTPException(status_code=404, detail="MISP integration not found")
    try:
        MispClient(credentials.base_url, credentials.api_key.get_secret_value())
        SecretStore(store).set(integration_id, {
            "base_url": credentials.base_url.rstrip("/"),
            "api_key": credentials.api_key.get_secret_value(),
        })
    except SecretConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    registry.update(integration_id, IntegrationUpdate(config={
        **integration.config,
        "base_url": credentials.base_url.rstrip("/"),
        "auth_configured": True,
    }))
    return {"status": "saved", "integration_id": integration_id, "secret_storage": "encrypted"}


@app.delete("/api/v1/integrations/{integration_id}/misp-credentials", tags=["integrations"])
def delete_misp_credentials(integration_id: str) -> Response:
    integration = registry.get(integration_id)
    if integration is None or integration.kind != "misp":
        raise HTTPException(status_code=404, detail="MISP integration not found")
    SecretStore(store).delete(integration_id)
    registry.update(integration_id, IntegrationUpdate(config={
        **integration.config, "auth_configured": False,
    }))
    return Response(status_code=204)


@app.get("/api/v1/integrations/{integration_id}/misp-diagnostics", tags=["integrations"])
def misp_diagnostics(integration_id: str) -> dict[str, object]:
    integration = registry.get(integration_id)
    if integration is None or integration.kind != "misp":
        raise HTTPException(status_code=404, detail="MISP integration not found")
    try:
        credentials = SecretStore(store).get(integration_id)
        if credentials is None:
            raise HTTPException(status_code=409, detail="MISP credentials are not configured")
        client = MispClient(str(credentials["base_url"]), str(credentials["api_key"]))
        return {
            "status": "connected",
            "integration_id": integration_id,
            **client.diagnostics(),
        }
    except SecretConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="Stored MISP credentials are invalid") from exc
    except MispError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


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
        client = MispClient(str(credentials["base_url"]), str(credentials["api_key"]))
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


@app.put("/api/v1/integrations/{integration_id}/wazuh-credentials", tags=["integrations"])
def save_wazuh_credentials(
    integration_id: str, credentials: WazuhCredentials
) -> dict[str, object]:
    integration = registry.get(integration_id)
    if integration is None or integration.kind != "wazuh":
        raise HTTPException(status_code=404, detail="Wazuh integration not found")
    username = credentials.username.get_secret_value()
    password = credentials.password.get_secret_value()
    try:
        WazuhClient(credentials.base_url, username, password)
        SecretStore(store).set(integration_id, {
            "base_url": credentials.base_url.rstrip("/"),
            "username": username,
            "password": password,
        })
    except SecretConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    registry.update(integration_id, IntegrationUpdate(config={
        **integration.config,
        "base_url": credentials.base_url.rstrip("/"),
        "auth_configured": True,
    }))
    return {"status": "saved", "integration_id": integration_id, "secret_storage": "encrypted"}


@app.delete("/api/v1/integrations/{integration_id}/wazuh-credentials", tags=["integrations"])
def delete_wazuh_credentials(integration_id: str) -> Response:
    integration = registry.get(integration_id)
    if integration is None or integration.kind != "wazuh":
        raise HTTPException(status_code=404, detail="Wazuh integration not found")
    SecretStore(store).delete(integration_id)
    registry.update(integration_id, IntegrationUpdate(config={
        **integration.config,
        "auth_configured": False,
    }))
    return Response(status_code=204)


@app.get("/api/v1/integrations/{integration_id}/wazuh-diagnostics", tags=["integrations"])
def wazuh_diagnostics(integration_id: str) -> dict[str, object]:
    integration = registry.get(integration_id)
    if integration is None or integration.kind != "wazuh":
        raise HTTPException(status_code=404, detail="Wazuh integration not found")
    try:
        credentials = SecretStore(store).get(integration_id)
        if credentials is None:
            raise HTTPException(status_code=409, detail="Wazuh credentials are not configured")
        client = WazuhClient(
            str(credentials["base_url"]),
            str(credentials["username"]),
            str(credentials["password"]),
        )
        return {
            "status": "connected",
            "integration_id": integration_id,
            **client.diagnostics(),
        }
    except SecretConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="Stored Wazuh credentials are invalid") from exc
    except WazuhError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.put("/api/v1/integrations/{integration_id}/prometheus-credentials", tags=["integrations"])
def save_prometheus_credentials(
    integration_id: str, credentials: PrometheusCredentials
) -> dict[str, object]:
    integration = registry.get(integration_id)
    if integration is None or integration.kind != "prometheus":
        raise HTTPException(status_code=404, detail="Prometheus integration not found")
    token = credentials.bearer_token.get_secret_value() if credentials.bearer_token else None
    try:
        PrometheusClient(credentials.base_url, token)
        SecretStore(store).set(integration_id, {
            "base_url": credentials.base_url.rstrip("/"), "bearer_token": token,
        })
    except SecretConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    registry.update(integration_id, IntegrationUpdate(config={
        **integration.config, "base_url": credentials.base_url.rstrip("/"), "auth_configured": True,
    }))
    return {"status": "saved", "integration_id": integration_id, "secret_storage": "encrypted",
            "authentication": "bearer" if token else "none"}


@app.delete("/api/v1/integrations/{integration_id}/prometheus-credentials", tags=["integrations"])
def delete_prometheus_credentials(integration_id: str) -> Response:
    integration = registry.get(integration_id)
    if integration is None or integration.kind != "prometheus":
        raise HTTPException(status_code=404, detail="Prometheus integration not found")
    SecretStore(store).delete(integration_id)
    registry.update(integration_id, IntegrationUpdate(config={
        **integration.config, "auth_configured": False,
    }))
    return Response(status_code=204)


@app.get("/api/v1/integrations/{integration_id}/prometheus-diagnostics", tags=["integrations"])
def prometheus_diagnostics(integration_id: str) -> dict[str, object]:
    integration = registry.get(integration_id)
    if integration is None or integration.kind != "prometheus":
        raise HTTPException(status_code=404, detail="Prometheus integration not found")
    try:
        credentials = SecretStore(store).get(integration_id)
        if credentials is None:
            raise HTTPException(status_code=409, detail="Prometheus configuration is not saved")
        client = PrometheusClient(
            str(credentials["base_url"]), str(credentials.get("bearer_token") or "") or None
        )
        return {"status": "connected", "integration_id": integration_id, **client.diagnostics()}
    except SecretConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="Stored Prometheus configuration is invalid") from exc
    except PrometheusError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.put("/api/v1/integrations/{integration_id}/grafana-credentials", tags=["integrations"])
def save_grafana_credentials(
    integration_id: str, credentials: GrafanaCredentials
) -> dict[str, object]:
    integration = registry.get(integration_id)
    if integration is None or integration.kind != "grafana":
        raise HTTPException(status_code=404, detail="Grafana integration not found")
    token = credentials.bearer_token.get_secret_value() if credentials.bearer_token else None
    try:
        GrafanaClient(credentials.base_url, token)
        SecretStore(store).set(integration_id, {
            "base_url": credentials.base_url.rstrip("/"),
            "bearer_token": token,
        })
    except SecretConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    registry.update(integration_id, IntegrationUpdate(config={
        **integration.config,
        "base_url": credentials.base_url.rstrip("/"),
        "auth_configured": True,
    }))
    return {
        "status": "saved",
        "integration_id": integration_id,
        "secret_storage": "encrypted",
        "authentication": "bearer" if token else "none",
    }


@app.delete("/api/v1/integrations/{integration_id}/grafana-credentials", tags=["integrations"])
def delete_grafana_credentials(integration_id: str) -> Response:
    integration = registry.get(integration_id)
    if integration is None or integration.kind != "grafana":
        raise HTTPException(status_code=404, detail="Grafana integration not found")
    SecretStore(store).delete(integration_id)
    registry.update(integration_id, IntegrationUpdate(config={
        **integration.config,
        "auth_configured": False,
    }))
    return Response(status_code=204)


@app.get("/api/v1/integrations/{integration_id}/grafana-diagnostics", tags=["integrations"])
def grafana_diagnostics(integration_id: str) -> dict[str, object]:
    integration = registry.get(integration_id)
    if integration is None or integration.kind != "grafana":
        raise HTTPException(status_code=404, detail="Grafana integration not found")
    try:
        credentials = SecretStore(store).get(integration_id)
        if credentials is None:
            raise HTTPException(status_code=409, detail="Grafana configuration is not saved")
        client = GrafanaClient(
            str(credentials["base_url"]),
            str(credentials.get("bearer_token") or "") or None,
        )
        return {
            "status": "connected",
            "integration_id": integration_id,
            **client.diagnostics(),
        }
    except SecretConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="Stored Grafana configuration is invalid") from exc
    except GrafanaError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


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
