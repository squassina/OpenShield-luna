import asyncio
import base64
import hashlib
import os
import secrets
import threading
import time
from psycopg import Connection
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from psycopg_pool import PoolTimeout

from openshield.api.routers.audit import create_audit_router
from openshield.api.routers.events import create_events_router
from openshield.api.routers.gateway import create_gateway_router
from openshield.api.routers.health import create_health_router
from openshield.api.routers.incidents import create_incidents_router
from openshield.api.routers.integration_credentials import create_integration_credentials_router
from openshield.api.routers.integration_tests import create_integration_test_router
from openshield.api.routers.integrations import create_integrations_router
from openshield.api.routers.inventory import create_inventory_router
from openshield.api.routers.metrics import create_metrics_router
from openshield.api.routers.openwrt_diagnostics import create_openwrt_diagnostics_router
from openshield.api.routers.policy_execution import create_policy_execution_router
from openshield.api.routers.privacy import create_privacy_router
from openshield.api.routers.reports import create_reports_router
from openshield.api.routers.sensor_credentials import create_sensor_credentials_router
from openshield.api.routers.threat_intel import create_threat_intel_router
from openshield.api.schemas import (
    AdGuardCredentials,
    AIInvestigationRequest,
    AIProviderCredentials,
    CrowdSecCredentials,
    GrafanaCredentials,
    IncidentStatusRequest,
    MispCredentials,
    OpenWrtCredentials,
    OPNsenseCredentials,
    PfSenseCredentials,
    PiHoleCredentials,
    PrometheusCredentials,
    ThreatIntelCredentials,
    WazuhCredentials,
)
from openshield.core.bootstrap import load_runtime_secrets
from openshield.core.logging import configure_logging
from openshield.core.metrics import MetricsRegistry
from openshield.core.rate_limits import RequestRateLimitMiddleware
from openshield.core.request_limits import RequestBodyLimitMiddleware
from openshield.core.secrets import SecretConfigurationError, SecretStore
from openshield.core.storage import PostgresStore
from openshield.core.tls import CABundleError, create_ssl_context
from openshield.execution.worker import run_expiration_loop
from openshield.gateway.registry import GatewayConnectionRegistry
from openshield.integrations.ai import AIProviderAdapter
from openshield.integrations.grafana import GrafanaAdapter
from openshield.integrations.openwrt import OpenWrtAdapter
from openshield.integrations.opnsense import OPNsenseAdapter
from openshield.integrations.pfsense import PfSenseAdapter
from openshield.integrations.prometheus import PrometheusAdapter
from openshield.integrations.registry import IntegrationRegistry
from openshield.integrations.threat_intel import ThreatIntelAdapter
from openshield.integrations.wazuh import WazuhAdapter
from openshield.privacy.adapter import DnsPrivacyAdapter
from openshield.privacy.polling import run_dns_polling_loop
from openshield.visibility.adapter import NetworkSensorAdapter

__all__ = ["AIInvestigationRequest", "AIProviderCredentials", "AdGuardCredentials", "CrowdSecCredentials", "GrafanaCredentials", "IncidentStatusRequest", "MispCredentials", "OPNsenseCredentials", "OpenWrtCredentials", "PfSenseCredentials", "PiHoleCredentials", "PrometheusCredentials", "ThreatIntelCredentials", "WazuhCredentials"]

load_runtime_secrets(create=True)
configure_logging()

@asynccontextmanager
async def _monitor_worker_lock(connection: Connection) -> None:
    """Detect a lost PostgreSQL session lock and stop this process's workers."""
    while True:
        await asyncio.sleep(10)
        await asyncio.to_thread(lambda: connection.execute("SELECT 1").fetchone())


async def _run_background_workers(interval_seconds: int) -> None:
    """Run database maintenance on one process across all Node replicas."""
    while True:
        try:
            lock_connection = await asyncio.to_thread(
                store.try_acquire_advisory_lock,
                "openshield:background-workers",
            )
        except Exception:
            metrics.increment("openshield_background_worker_lock_failures_total")
            logger.exception("Unable to acquire background worker lease")
            await asyncio.sleep(5)
            continue

        if lock_connection is None:
            metrics.increment("openshield_background_worker_lock_contention_total")
            await asyncio.sleep(5)
            continue

        metrics.increment("openshield_background_worker_lease_acquired_total")
        logger.info("Background worker lease acquired")
        tasks = [asyncio.create_task(run_expiration_loop(store, registry))]
        if interval_seconds:
            tasks.append(asyncio.create_task(
                run_dns_polling_loop(registry, store, metrics, interval_seconds)
            ))
        tasks.append(asyncio.create_task(_monitor_worker_lock(lock_connection)))

        try:
            done, _pending = await asyncio.wait(
                tasks,
                return_when=asyncio.FIRST_COMPLETED,
            )
            for completed in done:
                error = completed.exception()
                if error is not None:
                    raise error
            raise RuntimeError("Background worker or lease monitor stopped unexpectedly")
        except asyncio.CancelledError:
            raise
        except Exception:
            metrics.increment("openshield_background_worker_restarts_total")
            logger.exception("Background worker lease ended; retrying")
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await asyncio.to_thread(lock_connection.close)
            logger.warning("Background worker lease released")

        await asyncio.sleep(5)


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
    worker_task = asyncio.create_task(_run_background_workers(interval))
    try:
        yield
    finally:
        worker_task.cancel()
        try:
            await worker_task
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
app.add_middleware(
    RequestRateLimitMiddleware,
    ingestion_limit=int(os.getenv("OPENSHIELD_INGESTION_RATE_LIMIT", "120")),
    credential_limit=int(os.getenv("OPENSHIELD_SENSOR_CREDENTIAL_RATE_LIMIT", "10")),
    window_seconds=int(os.getenv("OPENSHIELD_RATE_LIMIT_WINDOW_SECONDS", "60")),
)


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



def _sensor_token_valid(integration_id: str, request: Request) -> bool:
    authorization = request.headers.get("authorization", "")
    if not authorization.startswith("Bearer "):
        return False
    token = authorization[7:]
    if not token:
        return False
    try:
        credentials = SecretStore(store).get(integration_id)
    except SecretConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    expected_hash = credentials.get("sensor_token_sha256") if credentials else None
    if not isinstance(expected_hash, str):
        return False
    supplied_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return secrets.compare_digest(supplied_hash, expected_hash)


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
    if is_gateway or path.endswith(("credentials", "-diagnostics")):
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

app.include_router(
    create_incidents_router(
        store=store,
        registry=registry,
    )
)


app.include_router(
    create_threat_intel_router(
        store=store,
        registry=registry,
        ssl_context_kwargs=_integration_ssl_context_kwargs,
    )
)


app.include_router(
    create_policy_execution_router(
        store=store,
        registry=registry,
        gateway_connections=gateway_connections,
    )
)

app.include_router(create_inventory_router(store=store))
app.include_router(
    create_events_router(
        store=store,
        registry=registry,
        metrics=metrics,
        gateway_token_valid=_gateway_token_valid,
        sensor_token_valid=_sensor_token_valid,
    )
)


app.include_router(
    create_openwrt_diagnostics_router(
        store=store,
        registry=registry,
        gateway_connections=gateway_connections,
    )
)

app.include_router(create_privacy_router(store=store, registry=registry, metrics=metrics))


app.include_router(create_audit_router(store=store))

app.include_router(
    create_reports_router(
        store=store,
        registry=registry,
        gateway_connections=gateway_connections,
    )
)

app.include_router(create_sensor_credentials_router(store=store, registry=registry))
