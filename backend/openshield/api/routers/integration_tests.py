import os
from collections.abc import Callable

from fastapi import APIRouter, HTTPException

from openshield.ai.providers import AIProviderError, test_ollama, test_openai
from openshield.core.secrets import SecretConfigurationError, SecretStore
from openshield.core.storage import PostgresStore
from openshield.integrations.crowdsec import CrowdSecClient, CrowdSecError
from openshield.integrations.grafana import GrafanaClient, GrafanaError
from openshield.integrations.models import Integration
from openshield.integrations.opnsense import OPNsenseClient, OPNsenseError
from openshield.integrations.pfsense import PfSenseClient, PfSenseError
from openshield.integrations.prometheus import PrometheusClient, PrometheusError
from openshield.integrations.registry import IntegrationRegistry
from openshield.integrations.wazuh import WazuhClient, WazuhError
from openshield.privacy.providers import DnsProviderError, fetch_dns_records
from openshield.threat_intel.providers import ThreatIntelProviderError, lookup_misp


SSLContextKwargs = Callable[[Integration, str], dict[str, object]]


def create_integration_test_router(
    *,
    store: PostgresStore,
    registry: IntegrationRegistry,
    ssl_context_kwargs: SSLContextKwargs,
) -> APIRouter:
    router = APIRouter()

    @router.post("/api/v1/integrations/{integration_id}/test", tags=["integrations"])
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
                    **ssl_context_kwargs(item, str(credentials["base_url"])),
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
                client = PfSenseClient(
                    str(credentials["base_url"]), str(credentials["api_key"]),
                    **ssl_context_kwargs(item, str(credentials["base_url"])),
                )
                system = client.get("/api/v2/status/system")
            except (KeyError, TypeError, ValueError) as exc:
                raise HTTPException(status_code=422, detail="Stored pfSense credentials are invalid") from exc
            except PfSenseError as exc:
                raise HTTPException(status_code=502, detail=str(exc)) from exc
            return {
                "status": "connected", "integration_id": integration_id, "provider": "pfsense",
                "system_information_available": bool(system), "imported": 0,
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
                    **ssl_context_kwargs(item, str(credentials["base_url"])),
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
                    str(credentials["base_url"]),
                    str(credentials.get("bearer_token") or "") or None,
                    **ssl_context_kwargs(item, str(credentials["base_url"])),
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
                    **ssl_context_kwargs(item, str(credentials["base_url"])),
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
                encrypted = store.get_integration_secret(integration_id)
                credentials = SecretStore(store).get(integration_id) if encrypted else None
                records = fetch_dns_records(item, credentials)
            except SecretConfigurationError as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from exc
            except DnsProviderError as exc:
                raise HTTPException(status_code=502, detail=str(exc)) from exc
            return {
                "status": "connected",
                "integration_id": integration_id,
                "provider": item.kind,
                "records_available": len(records),
                "imported": 0,
            }
        if item.kind == "crowdsec":
            try:
                secret = SecretStore(store).get(integration_id)
            except SecretConfigurationError as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from exc
            if not secret:
                raise HTTPException(status_code=409, detail="CrowdSec credentials are not configured")
            if not isinstance(secret.get("bouncer_api_key"), str) or not secret["bouncer_api_key"]:
                raise HTTPException(
                    status_code=409,
                    detail="CrowdSec Local API bouncer credentials are not configured",
                )
            try:
                diagnostics = CrowdSecClient(
                    str(secret["base_url"]),
                    secret["bouncer_api_key"],
                    str(secret.get("machine_id") or "") or None,
                    str(secret.get("machine_password") or "") or None,
                    **ssl_context_kwargs(item, str(secret["base_url"])),
                ).diagnostics()
            except (KeyError, TypeError, ValueError) as exc:
                raise HTTPException(status_code=422, detail="Stored CrowdSec credentials are invalid") from exc
            except CrowdSecError as exc:
                raise HTTPException(status_code=502, detail=str(exc)) from exc
            summary = diagnostics["summary"]
            return {
                "status": "connected", "integration_id": integration_id, "provider": "crowdsec",
                "alerts_available": summary["alerts_available"],
                "decisions_available": summary["decisions_available"], "imported": 0,
            }
        if item.kind == "misp":
            try:
                secret = SecretStore(store).get(integration_id)
            except SecretConfigurationError as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from exc
            api_key = secret.get("api_key") if secret else None
            base_url = item.config.get("base_url")
            if not isinstance(api_key, str) or not api_key:
                raise HTTPException(status_code=409, detail="MISP API key is not configured")
            if not isinstance(base_url, str):
                raise HTTPException(status_code=422, detail="MISP base URL is not configured")
            try:
                result = lookup_misp(
                    base_url, api_key, "ip", "192.0.2.1",
                    **ssl_context_kwargs(item, base_url),
                )
            except (ThreatIntelProviderError, ValueError) as exc:
                raise HTTPException(status_code=502, detail=str(exc)) from exc
            return {
                "status": "connected", "integration_id": integration_id, "provider": "misp",
                "matches": len(result.get("attributes", [])),
                "message": "Provider authentication and API request succeeded.",
            }
        if item.kind == "ollama":
            base_url = item.config.get("base_url", "http://localhost:11434")
            if not isinstance(base_url, str):
                raise HTTPException(status_code=422, detail="Ollama base URL is invalid")
            try:
                models = test_ollama(
                    base_url, **ssl_context_kwargs(item, base_url)
                )
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
                models = test_openai(
                    api_key, **ssl_context_kwargs(item, "https://api.openai.com")
                )
            except (AIProviderError, ValueError) as exc:
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



    return router
