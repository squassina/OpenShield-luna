import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from openshield.api.main import app

client = TestClient(app)
ADMIN_KEY = "a" * 64
OPERATOR_KEY = "b" * 64
READER_KEY = "c" * 64
GATEWAY_KEY = "d" * 64


@pytest.fixture(autouse=True)
def configure_test_api_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    records = [
        ("test-admin", "admin", ADMIN_KEY),
        ("test-operator", "operator", OPERATOR_KEY),
        ("test-reader", "reader", READER_KEY),
        ("test-gateway", "gateway", GATEWAY_KEY),
    ]
    config = [
        {
            "key_id": key_id,
            "role": role,
            "key_hash": hashlib.sha256(secret.encode()).hexdigest(),
        }
        for key_id, role, secret in records
    ]
    monkeypatch.setenv("OPENSHIELD_API_KEYS", json.dumps(config))


def setup_function() -> None:
    from openshield.api import main

    main.registry._integrations.clear()
    main.events.clear()


def headers(key: str = ADMIN_KEY) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def register_gateway() -> None:
    response = client.post(
        "/api/v1/integrations",
        headers=headers(),
        json={
            "integration_id": "router-lab",
            "kind": "openwrt",
            "display_name": "Lab router",
            "config": {"base_url": "https://192.0.2.1"},
        },
    )
    assert response.status_code == 201


def sample_event(event_id: str = "event-001") -> dict[str, object]:
    return {
        "schema_version": "openshield.event.v1",
        "event_id": event_id,
        "source": {"integration_id": "router-lab", "kind": "openwrt"},
        "event_type": "gateway.health",
        "occurred_at": "2026-01-01T12:00:00Z",
        "observed_at": "2026-01-01T12:00:01Z",
        "severity": "info",
        "payload": {"status": "reachable"},
    }


def test_health_endpoints_remain_public() -> None:
    assert client.get("/health/live").json() == {"status": "alive"}
    assert client.get("/health/ready").json() == {"status": "ready"}


def test_protected_endpoint_requires_bearer_key() -> None:
    response = client.get("/api/v1/integrations")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_invalid_api_key_is_rejected() -> None:
    response = client.get("/api/v1/integrations", headers=headers("invalid"))
    assert response.status_code == 401


def test_invalid_auth_configuration_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENSHIELD_API_KEYS", "not-json")
    response = client.get("/api/v1/integrations", headers=headers())
    assert response.status_code == 503


def test_reader_can_read_but_cannot_register() -> None:
    response = client.get("/api/v1/integrations", headers=headers(READER_KEY))
    assert response.status_code == 200

    response = client.post(
        "/api/v1/integrations",
        headers=headers(READER_KEY),
        json={
            "integration_id": "router-lab",
            "kind": "openwrt",
            "display_name": "Lab router",
        },
    )
    assert response.status_code == 403


def test_gateway_can_ingest_but_cannot_read_events() -> None:
    register_gateway()
    response = client.post(
        "/api/v1/events",
        headers=headers(GATEWAY_KEY),
        json=sample_event(),
    )
    assert response.status_code == 202

    response = client.get("/api/v1/events", headers=headers(GATEWAY_KEY))
    assert response.status_code == 403


def test_register_openwrt_and_probe() -> None:
    register_gateway()
    response = client.get(
        "/api/v1/integrations/router-lab/probe",
        headers=headers(),
    )
    assert response.status_code == 200
    assert response.json()["transport"] == "not_connected"
    assert "read_events" in response.json()["capabilities"]


def test_duplicate_integration_is_rejected() -> None:
    register_gateway()
    response = client.post(
        "/api/v1/integrations",
        headers=headers(),
        json={"integration_id": "router-lab", "kind": "openwrt", "display_name": "Duplicate"},
    )
    assert response.status_code == 409


def test_unknown_integration_kind_is_rejected() -> None:
    response = client.post(
        "/api/v1/integrations",
        headers=headers(),
        json={"integration_id": "unknown-lab", "kind": "unknown", "display_name": "Unknown"},
    )
    assert response.status_code == 400


def test_ingest_event_preserves_source_provenance() -> None:
    register_gateway()
    response = client.post(
        "/api/v1/events",
        headers=headers(),
        json=sample_event(),
    )
    assert response.status_code == 202
    stored = client.get("/api/v1/events", headers=headers()).json()
    assert stored[0]["source"]["integration_id"] == "router-lab"


def test_event_from_unknown_source_is_rejected() -> None:
    response = client.post(
        "/api/v1/events",
        headers=headers(),
        json=sample_event(),
    )
    assert response.status_code == 400


def test_event_source_kind_must_match_registered_integration() -> None:
    register_gateway()
    event = sample_event()
    event["source"] = {"integration_id": "router-lab", "kind": "other"}
    response = client.post("/api/v1/events", headers=headers(), json=event)
    assert response.status_code == 400


def test_event_rejects_unknown_schema_version() -> None:
    event = sample_event()
    event["schema_version"] = "openshield.event.v2"
    response = client.post("/api/v1/events", headers=headers(), json=event)
    assert response.status_code == 422
