import hashlib
import os

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from openshield.api.main import app
from openshield.core.secrets import SecretStore

client = TestClient(app)


def setup_function() -> None:
    os.environ["OPENSHIELD_SECRET_KEY"] = Fernet.generate_key().decode()
    os.environ["OPENSHIELD_API_AUTH_ENABLED"] = "false"
    from openshield.api import main

    main.store.reset()


def register_sensor(integration_id: str) -> None:
    response = client.post("/api/v1/integrations", json={
        "integration_id": integration_id,
        "kind": "zeek",
        "display_name": integration_id,
    })
    assert response.status_code == 201


def sensor_record() -> dict[str, object]:
    return {"_path": "conn", "ts": 1760000000, "uid": "C-test-1"}


def issue_token(integration_id: str) -> str:
    response = client.put(f"/api/v1/sensors/{integration_id}/credentials")
    assert response.status_code == 200
    assert response.json()["status"] == "rotated"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    return response.json()["token"]


def ingest(integration_id: str, token: str) -> int:
    response = client.post(
        f"/api/v1/sensors/{integration_id}/events",
        headers={"Authorization": f"Bearer {token}"},
        json=[sensor_record()],
    )
    return response.status_code


def test_sensor_ingestion_rejects_missing_and_invalid_credentials() -> None:
    register_sensor("sensor-lab")

    assert client.post(
        "/api/v1/sensors/sensor-lab/events",
        json=[sensor_record()],
    ).status_code == 401
    assert ingest("sensor-lab", "invalid-token") == 401
    assert client.get("/api/v1/events").json()["items"] == []


def test_sensor_credentials_are_scoped_rotatable_and_revocable() -> None:
    register_sensor("sensor-a")
    register_sensor("sensor-b")
    token_a = issue_token("sensor-a")

    assert ingest("sensor-a", token_a) == 202
    assert ingest("sensor-b", token_a) == 401

    token_a_rotated = issue_token("sensor-a")
    assert ingest("sensor-a", token_a) == 401
    assert ingest("sensor-a", token_a_rotated) == 202

    revoked = client.delete("/api/v1/sensors/sensor-a/credentials")
    assert revoked.status_code == 204
    assert ingest("sensor-a", token_a_rotated) == 401


def test_sensor_token_is_hashed_at_rest_and_never_audited(monkeypatch) -> None:
    from openshield.api import main

    register_sensor("sensor-lab")
    token = issue_token("sensor-lab")
    stored = SecretStore(main.store).get("sensor-lab")

    assert stored == {
        "sensor_token_sha256": hashlib.sha256(token.encode("utf-8")).hexdigest(),
    }
    assert token not in str(stored)

    assert ingest("sensor-lab", "wrong-secret") == 401
    audit = client.get("/api/v1/audit").json()
    failed = next(
        item for item in audit
        if item["action"] == "sensor.ingestion.authentication_failed"
    )
    assert failed["target_id"] == "sensor-lab"
    assert "wrong-secret" not in str(failed)
    assert token not in str(audit)


def test_sensor_credentials_reject_non_sensor_integrations() -> None:
    response = client.post("/api/v1/integrations", json={
        "integration_id": "router-lab",
        "kind": "openwrt",
        "display_name": "Router",
    })
    assert response.status_code == 201
    assert client.put("/api/v1/sensors/router-lab/credentials").status_code == 404
    assert client.delete("/api/v1/sensors/router-lab/credentials").status_code == 404


def test_generic_event_ingestion_cannot_bypass_sensor_authentication() -> None:
    from datetime import UTC, datetime

    register_sensor("sensor-lab")
    token = issue_token("sensor-lab")
    now = datetime.now(UTC).isoformat()
    event = {
        "schema_version": "openshield.event.v1",
        "event_id": "generic-sensor-event",
        "source": {"integration_id": "sensor-lab", "kind": "zeek"},
        "event_type": "network.zeek.conn",
        "occurred_at": now,
        "observed_at": now,
        "severity": "info",
        "payload": {},
    }

    assert client.post("/api/v1/events", json=event).status_code == 401
    accepted = client.post(
        "/api/v1/events",
        json=event,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert accepted.status_code == 202


def test_business_admin_auth_protects_sensor_enrollment_and_credential_management(
    monkeypatch,
) -> None:
    import base64

    register_sensor("sensor-lab")
    monkeypatch.setenv("OPENSHIELD_API_AUTH_ENABLED", "true")
    monkeypatch.setenv("OPENSHIELD_API_USERNAME", "admin")
    monkeypatch.setenv("OPENSHIELD_API_PASSWORD", "strong-test-password")

    assert client.post("/api/v1/integrations", json={
        "integration_id": "sensor-other",
        "kind": "zeek",
        "display_name": "Other sensor",
    }).status_code == 401
    assert client.put("/api/v1/sensors/sensor-lab/credentials").status_code == 401

    credentials = base64.b64encode(b"admin:strong-test-password").decode()
    admin_headers = {"Authorization": f"Basic {credentials}"}
    rotated = client.put(
        "/api/v1/sensors/sensor-lab/credentials",
        headers=admin_headers,
    )
    assert rotated.status_code == 200

    # Admin credentials do not substitute for the sensor's integration-scoped token.
    assert client.post(
        "/api/v1/sensors/sensor-lab/events",
        headers=admin_headers,
        json=[sensor_record()],
    ).status_code == 401
