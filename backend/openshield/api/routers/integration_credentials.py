import os
from collections.abc import Callable
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, Response

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
from openshield.core.secrets import SecretConfigurationError, SecretStore
from openshield.core.storage import PostgresStore
from openshield.integrations.crowdsec import CrowdSecClient, CrowdSecError
from openshield.integrations.grafana import GrafanaClient, GrafanaError
from openshield.integrations.misp import MispClient, MispError
from openshield.integrations.models import Integration, IntegrationUpdate
from openshield.integrations.openwrt_rpc import OpenWrtRPCClient
from openshield.integrations.opnsense import OPNsenseClient, OPNsenseError
from openshield.integrations.pfsense import PfSenseClient, PfSenseError
from openshield.integrations.prometheus import PrometheusClient, PrometheusError
from openshield.integrations.registry import IntegrationRegistry
from openshield.integrations.wazuh import WazuhClient, WazuhError


SSLContextKwargs = Callable[[Integration, str], dict[str, object]]


def create_integration_credentials_router(
    *,
    store: PostgresStore,
    registry: IntegrationRegistry,
    ssl_context_kwargs: SSLContextKwargs,
) -> APIRouter:
    router = APIRouter()

    @router.put("/api/v1/integrations/{integration_id}/opnsense-credentials", tags=["integrations"])
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


    @router.delete("/api/v1/integrations/{integration_id}/opnsense-credentials", tags=["integrations"])
    def delete_opnsense_credentials(integration_id: str) -> Response:
        integration = registry.get(integration_id)
        if integration is None or integration.kind != "opnsense":
            raise HTTPException(status_code=404, detail="OPNsense integration not found")
        SecretStore(store).delete(integration_id)
        registry.update(integration_id, IntegrationUpdate(config={
            **integration.config, "auth_configured": False,
        }))
        return Response(status_code=204)


    @router.get("/api/v1/integrations/{integration_id}/opnsense-diagnostics", tags=["integrations"])
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
                **_integration_ssl_context_kwargs(integration, str(credentials["base_url"])),
            )
            return {"status": "connected", "integration_id": integration_id, **client.diagnostics()}
        except SecretConfigurationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail="Stored OPNsense credentials are invalid") from exc
        except OPNsenseError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc


    @router.put("/api/v1/integrations/{integration_id}/pfsense-credentials", tags=["integrations"])
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


    @router.delete("/api/v1/integrations/{integration_id}/pfsense-credentials", tags=["integrations"])
    def delete_pfsense_credentials(integration_id: str) -> Response:
        integration = registry.get(integration_id)
        if integration is None or integration.kind != "pfsense":
            raise HTTPException(status_code=404, detail="pfSense integration not found")
        SecretStore(store).delete(integration_id)
        registry.update(integration_id, IntegrationUpdate(config={
            **integration.config, "auth_configured": False,
        }))
        return Response(status_code=204)


    @router.get("/api/v1/integrations/{integration_id}/pfsense-diagnostics", tags=["integrations"])
    def pfsense_diagnostics(integration_id: str) -> dict[str, object]:
        integration = registry.get(integration_id)
        if integration is None or integration.kind != "pfsense":
            raise HTTPException(status_code=404, detail="pfSense integration not found")
        try:
            credentials = SecretStore(store).get(integration_id)
            if credentials is None:
                raise HTTPException(status_code=409, detail="pfSense API key is not configured")
            client = PfSenseClient(
                str(credentials["base_url"]), str(credentials["api_key"]),
                **_integration_ssl_context_kwargs(integration, str(credentials["base_url"])),
            )
            return {"status": "connected", "integration_id": integration_id, **client.diagnostics()}
        except SecretConfigurationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail="Stored pfSense credentials are invalid") from exc
        except PfSenseError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc


    @router.put("/api/v1/integrations/{integration_id}/crowdsec-credentials", tags=["integrations"])
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


    @router.delete("/api/v1/integrations/{integration_id}/crowdsec-credentials", tags=["integrations"])
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


    @router.get("/api/v1/integrations/{integration_id}/crowdsec-diagnostics", tags=["integrations"])
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
                **_integration_ssl_context_kwargs(integration, str(credentials["base_url"])),
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


    @router.put("/api/v1/integrations/{integration_id}/misp-credentials", tags=["integrations"])
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


    @router.delete("/api/v1/integrations/{integration_id}/misp-credentials", tags=["integrations"])
    def delete_misp_credentials(integration_id: str) -> Response:
        integration = registry.get(integration_id)
        if integration is None or integration.kind != "misp":
            raise HTTPException(status_code=404, detail="MISP integration not found")
        SecretStore(store).delete(integration_id)
        registry.update(integration_id, IntegrationUpdate(config={
            **integration.config, "auth_configured": False,
        }))
        return Response(status_code=204)


    @router.get("/api/v1/integrations/{integration_id}/misp-diagnostics", tags=["integrations"])
    def misp_diagnostics(integration_id: str) -> dict[str, object]:
        integration = registry.get(integration_id)
        if integration is None or integration.kind != "misp":
            raise HTTPException(status_code=404, detail="MISP integration not found")
        try:
            credentials = SecretStore(store).get(integration_id)
            if credentials is None:
                raise HTTPException(status_code=409, detail="MISP credentials are not configured")
            client = MispClient(
                str(credentials["base_url"]), str(credentials["api_key"]),
                **_integration_ssl_context_kwargs(integration, str(credentials["base_url"])),
            )
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


    @router.put("/api/v1/integrations/{integration_id}/wazuh-credentials", tags=["integrations"])
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


    @router.delete("/api/v1/integrations/{integration_id}/wazuh-credentials", tags=["integrations"])
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


    @router.get("/api/v1/integrations/{integration_id}/wazuh-diagnostics", tags=["integrations"])
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
                **_integration_ssl_context_kwargs(integration, str(credentials["base_url"])),
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


    @router.put("/api/v1/integrations/{integration_id}/prometheus-credentials", tags=["integrations"])
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


    @router.delete("/api/v1/integrations/{integration_id}/prometheus-credentials", tags=["integrations"])
    def delete_prometheus_credentials(integration_id: str) -> Response:
        integration = registry.get(integration_id)
        if integration is None or integration.kind != "prometheus":
            raise HTTPException(status_code=404, detail="Prometheus integration not found")
        SecretStore(store).delete(integration_id)
        registry.update(integration_id, IntegrationUpdate(config={
            **integration.config, "auth_configured": False,
        }))
        return Response(status_code=204)


    @router.get("/api/v1/integrations/{integration_id}/prometheus-diagnostics", tags=["integrations"])
    def prometheus_diagnostics(integration_id: str) -> dict[str, object]:
        integration = registry.get(integration_id)
        if integration is None or integration.kind != "prometheus":
            raise HTTPException(status_code=404, detail="Prometheus integration not found")
        try:
            credentials = SecretStore(store).get(integration_id)
            if credentials is None:
                raise HTTPException(status_code=409, detail="Prometheus configuration is not saved")
            client = PrometheusClient(
                str(credentials["base_url"]), str(credentials.get("bearer_token") or "") or None,
                **_integration_ssl_context_kwargs(integration, str(credentials["base_url"])),
            )
            return {"status": "connected", "integration_id": integration_id, **client.diagnostics()}
        except SecretConfigurationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail="Stored Prometheus configuration is invalid") from exc
        except PrometheusError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc


    @router.put("/api/v1/integrations/{integration_id}/grafana-credentials", tags=["integrations"])
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


    @router.delete("/api/v1/integrations/{integration_id}/grafana-credentials", tags=["integrations"])
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


    @router.get("/api/v1/integrations/{integration_id}/grafana-diagnostics", tags=["integrations"])
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
                **_integration_ssl_context_kwargs(integration, str(credentials["base_url"])),
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


    @router.put("/api/v1/integrations/{integration_id}/ai-credentials", tags=["integrations"])
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


    @router.delete("/api/v1/integrations/{integration_id}/ai-credentials", status_code=204, tags=["integrations"])
    def delete_ai_credentials(integration_id: str) -> Response:
        integration = registry.get(integration_id)
        if integration is None or integration.kind != "openai":
            raise HTTPException(status_code=404, detail="OpenAI integration not found")
        store.delete_integration_secret(integration_id)
        return Response(status_code=204)


    @router.put("/api/v1/integrations/{integration_id}/threat-intel-credentials", tags=["integrations"])
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


    @router.delete("/api/v1/integrations/{integration_id}/threat-intel-credentials", status_code=204, tags=["integrations"])
    def delete_threat_intel_credentials(integration_id: str) -> Response:
        integration = registry.get(integration_id)
        if integration is None or integration.kind not in {"crowdsec", "misp"}:
            raise HTTPException(status_code=404, detail="Threat intelligence integration not found")
        store.delete_integration_secret(integration_id)
        return Response(status_code=204)


    @router.put("/api/v1/integrations/{integration_id}/openwrt-credentials", tags=["integrations"])
    def save_openwrt_credentials(
        integration_id: str, credentials: OpenWrtCredentials
    ) -> dict[str, object]:
        integration = registry.get(integration_id)
        if integration is None or integration.kind != "openwrt":
            raise HTTPException(status_code=404, detail="OpenWrt integration not found")
        if not os.getenv("OPENSHIELD_GATEWAY_TOKEN"):
            raise HTTPException(
                status_code=503,
                detail="Local Gateway Connector authentication is not initialized; check the connector service",
            )
        try:
            parsed = urlsplit(credentials.base_url)
            if (
                parsed.scheme not in {"http", "https"} or not parsed.netloc
                or parsed.username or parsed.password or parsed.query or parsed.fragment
            ):
                raise ValueError("OpenWrt URL must be an absolute HTTP(S) URL without credentials")
            OpenWrtRPCClient(
                credentials.base_url,
                credentials.username,
                credentials.password.get_secret_value(),
            )
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


    @router.delete("/api/v1/integrations/{integration_id}/openwrt-credentials", tags=["integrations"])
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


    @router.put("/api/v1/integrations/{integration_id}/dns-provider-credentials", tags=["integrations"])
    def save_dns_provider_credentials(integration_id: str, credentials: PiHoleCredentials | AdGuardCredentials) -> dict[str, object]:
        integration = registry.get(integration_id)
        if integration is None or integration.kind not in {"pihole", "adguard"}:
            raise HTTPException(status_code=404, detail="DNS provider integration not found")
        if integration.kind == "pihole" and not isinstance(credentials, PiHoleCredentials):
            raise HTTPException(status_code=422, detail="Pi-hole requires a password")
        if integration.kind == "adguard" and not isinstance(credentials, AdGuardCredentials):
            raise HTTPException(status_code=422, detail="AdGuard requires a username and password")
        values = ({"password": credentials.password.get_secret_value()} if isinstance(credentials, PiHoleCredentials)
                  else {"username": credentials.username.get_secret_value(), "password": credentials.password.get_secret_value()})
        try:
            SecretStore(store).set(integration_id, values)
        except SecretConfigurationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        return {"status": "saved", "integration_id": integration_id, "credentials_configured": True, "secret_storage": "encrypted"}


    @router.delete("/api/v1/integrations/{integration_id}/dns-provider-credentials", status_code=204, tags=["integrations"])
    def delete_dns_provider_credentials(integration_id: str) -> Response:
        integration = registry.get(integration_id)
        if integration is None or integration.kind not in {"pihole", "adguard"}:
            raise HTTPException(status_code=404, detail="DNS provider integration not found")
        store.delete_integration_secret(integration_id)
        return Response(status_code=204)

    return router
