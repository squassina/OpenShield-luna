import hashlib
import secrets

from fastapi import APIRouter, HTTPException, Response

from openshield.core.secrets import SecretConfigurationError, SecretStore
from openshield.core.storage import PostgresStore
from openshield.integrations.registry import IntegrationRegistry


def create_sensor_credentials_router(
    *,
    store: PostgresStore,
    registry: IntegrationRegistry,
) -> APIRouter:
    router = APIRouter()

    @router.put("/api/v1/sensors/{integration_id}/credentials", tags=["sensors"])
    def rotate_sensor_credentials(integration_id: str) -> dict[str, str]:
        integration = registry.get(integration_id)
        if integration is None or integration.kind not in {"suricata", "zeek"}:
            raise HTTPException(status_code=404, detail="Network sensor integration not found")
        token = secrets.token_urlsafe(32)
        try:
            credentials = SecretStore(store)
            values = credentials.get(integration_id) or {}
            values["sensor_token_sha256"] = hashlib.sha256(token.encode("utf-8")).hexdigest()
            credentials.set(integration_id, values)
        except SecretConfigurationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        store.write_audit(
            "sensor.credentials.rotated",
            None,
            integration_id,
            {"credential_type": "sensor_bearer"},
        )
        return {"status": "rotated", "integration_id": integration_id, "token": token}

    @router.delete(
        "/api/v1/sensors/{integration_id}/credentials",
        status_code=204,
        tags=["sensors"],
    )
    def revoke_sensor_credentials(integration_id: str) -> Response:
        integration = registry.get(integration_id)
        if integration is None or integration.kind not in {"suricata", "zeek"}:
            raise HTTPException(status_code=404, detail="Network sensor integration not found")
        try:
            credentials = SecretStore(store)
            values = credentials.get(integration_id)
            if values is not None:
                values.pop("sensor_token_sha256", None)
                if values:
                    credentials.set(integration_id, values)
                else:
                    credentials.delete(integration_id)
        except SecretConfigurationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        store.write_audit(
            "sensor.credentials.revoked",
            None,
            integration_id,
            {"credential_type": "sensor_bearer"},
        )
        return Response(status_code=204)

    return router
