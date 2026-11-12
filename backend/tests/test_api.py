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
    main.gateway_connections._connections.clear()


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


def test_health_endpoints_remain_public_but_readiness_requires_auth_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert client.get("/health/live").json() == {"status": "alive"}
    assert client.get("/health/ready").json() == {"status": "ready"}

    monkeypatch.setenv("OPENSHIELD_API_KEYS", "")
    assert client.get("/health/live").status_code == 200
    assert client.get("/health/ready").status_code == 503


def test_protected_endpoint_requires_bearer_key() -> None:
    response = client.get("/api/v1/integrations")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_invalid_api_key_is_rejected() -> None:
    response = client.get("/api/v1/integrations", headers=headers("x" * 64))
    assert response.status_code == 401


def test_short_api_key_is_rejected() -> None:
    response = client.get("/api/v1/integrations", headers=headers("short"))
    assert response.status_code == 401


def test_invalid_auth_configuration_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENSHIELD_API_KEYS", "not-json")
    response = client.get("/api/v1/integrations", headers=headers())
    assert response.status_code == 503


def test_duplicate_key_ids_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    key_hash = hashlib.sha256(ADMIN_KEY.encode()).hexdigest()
    records = [
        {"key_id": "duplicate", "role": "admin", "key_hash": key_hash},
        {"key_id": "duplicate", "role": "reader", "key_hash": hashlib.sha256(READER_KEY.encode()).hexdigest()},
    ]
    monkeypatch.setenv("OPENSHIELD_API_KEYS", json.dumps(records))
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


def test_operator_can_ingest_but_cannot_manage_integrations() -> None:
    response = client.post(
        "/api/v1/integrations",
        headers=headers(OPERATOR_KEY),
        json={
            "integration_id": "router-lab",
            "kind": "openwrt",
            "display_name": "Lab router",
        },
    )
    assert response.status_code == 403

    register_gateway()
    response = client.post(
        "/api/v1/events",
        headers=headers(OPERATOR_KEY),
        json=sample_event(),
    )
    assert response.status_code == 202


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



def gateway_connect_payload() -> dict[str, object]:
    return {
        "protocol_version": "openshield.gateway.v1",
        "gateway_id": "test-gateway",
        "gateway_type": "openwrt",
        "connector_version": "0.1.0",
        "capabilities": ["discover", "health_check", "read_events"],
    }


def test_gateway_connect_requires_gateway_role_and_binds_identity() -> None:
    response = client.post(
        "/api/v1/gateway/connect",
        headers=headers(GATEWAY_KEY),
        json=gateway_connect_payload(),
    )
    assert response.status_code == 201
    assert response.json()["status"] == "connected"
    assert response.json()["accepted_capabilities"] == [
        "discover",
        "health_check",
        "read_events",
    ]

    mismatch = gateway_connect_payload()
    mismatch["gateway_id"] = "another-gateway"
    response = client.post(
        "/api/v1/gateway/connect",
        headers=headers(GATEWAY_KEY),
        json=mismatch,
    )
    assert response.status_code == 403


def test_gateway_heartbeat_requires_existing_connection() -> None:
    heartbeat = {"protocol_version": "openshield.gateway.v1"}
    response = client.post(
        "/api/v1/gateway/heartbeat",
        headers=headers(GATEWAY_KEY),
        json=heartbeat,
    )
    assert response.status_code == 409

    client.post(
        "/api/v1/gateway/connect",
        headers=headers(GATEWAY_KEY),
        json=gateway_connect_payload(),
    )
    response = client.post(
        "/api/v1/gateway/heartbeat",
        headers=headers(GATEWAY_KEY),
        json=heartbeat,
    )
    assert response.status_code == 200
    assert response.json()["status"] == "acknowledged"


def test_gateway_cannot_advertise_enforcement_capabilities() -> None:
    payload = gateway_connect_payload()
    payload["capabilities"] = ["execute_action"]
    response = client.post(
        "/api/v1/gateway/connect",
        headers=headers(GATEWAY_KEY),
        json=payload,
    )
    assert response.status_code == 422


def test_gateway_status_is_admin_only() -> None:
    client.post(
        "/api/v1/gateway/connect",
        headers=headers(GATEWAY_KEY),
        json=gateway_connect_payload(),
    )
    response = client.get("/api/v1/gateways", headers=headers(GATEWAY_KEY))
    assert response.status_code == 403

    response = client.get("/api/v1/gateways", headers=headers())
    assert response.status_code == 200
    assert response.json()[0]["status"] == "connected"


def test_gateway_protocol_version_is_validated() -> None:
    payload = gateway_connect_payload()
    payload["protocol_version"] = "openshield.gateway.v2"
    response = client.post(
        "/api/v1/gateway/connect",
        headers=headers(GATEWAY_KEY),
        json=payload,
    )
    assert response.status_code == 422


def test_register_openwrt_and_probe() -> None:
    register_gateway()
    response = client.get(
        "/api/v1/integrations/router-lab/probe",
        headers=headers(),
    )
    assert response.status_code == 200
    assert response.json()["transport"] == "ubus_rpc"
    assert response.json()["capabilities"] == ["health_check", "discover"]


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



def test_integration_registration_rejects_secrets_in_config() -> None:
    response = client.post(
        "/api/v1/integrations",
        headers=headers(),
        json={
            "integration_id": "router-secret",
            "kind": "openwrt",
            "display_name": "Router",
            "config": {"base_url": "http://192.0.2.1", "password": "must-not-be-stored"},
        },
    )
    assert response.status_code == 422
