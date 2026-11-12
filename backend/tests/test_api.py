from fastapi.testclient import TestClient

from openshield.api.main import app

client = TestClient(app)


def setup_function() -> None:
    from openshield.api import main

    main.registry._integrations.clear()
    main.events.clear()


def register_gateway() -> None:
    response = client.post(
        "/api/v1/integrations",
        json={
            "integration_id": "router-lab",
            "kind": "openwrt",
            "display_name": "Lab router",
            "config": {"base_url": "https://192.0.2.1"},
        },
    )
    assert response.status_code == 201


def test_health_endpoints() -> None:
    assert client.get("/health/live").json() == {"status": "alive"}
    assert client.get("/health/ready").json() == {"status": "ready"}


def test_register_openwrt_and_probe() -> None:
    register_gateway()
    response = client.get("/api/v1/integrations/router-lab/probe")
    assert response.status_code == 200
    assert response.json()["transport"] == "not_connected"
    assert "read_events" in response.json()["capabilities"]


def test_duplicate_integration_is_rejected() -> None:
    register_gateway()
    response = client.post(
        "/api/v1/integrations",
        json={"integration_id": "router-lab", "kind": "openwrt", "display_name": "Duplicate"},
    )
    assert response.status_code == 409


def test_unknown_integration_kind_is_rejected() -> None:
    response = client.post(
        "/api/v1/integrations",
        json={"integration_id": "unknown-lab", "kind": "unknown", "display_name": "Unknown"},
    )
    assert response.status_code == 400


def test_ingest_event_preserves_source_provenance() -> None:
    register_gateway()
    event = {
        "schema_version": "openshield.event.v1",
        "event_id": "event-001",
        "source": {"integration_id": "router-lab", "kind": "openwrt"},
        "event_type": "gateway.health",
        "occurred_at": "2026-01-01T12:00:00Z",
        "observed_at": "2026-01-01T12:00:01Z",
        "severity": "info",
        "payload": {"status": "reachable"},
    }
    assert client.post("/api/v1/events", json=event).status_code == 202
    stored = client.get("/api/v1/events").json()
    assert stored[0]["source"]["integration_id"] == "router-lab"


def test_event_from_unknown_source_is_rejected() -> None:
    event = {
        "schema_version": "openshield.event.v1",
        "event_id": "event-002",
        "source": {"integration_id": "missing", "kind": "openwrt"},
        "event_type": "gateway.health",
        "occurred_at": "2026-01-01T12:00:00Z",
        "observed_at": "2026-01-01T12:00:01Z",
        "severity": "info",
        "payload": {},
    }
    assert client.post("/api/v1/events", json=event).status_code == 400


def test_event_source_kind_must_match_registered_integration() -> None:
    register_gateway()
    event = {
        "schema_version": "openshield.event.v1",
        "event_id": "event-003",
        "source": {"integration_id": "router-lab", "kind": "other"},
        "event_type": "gateway.health",
        "occurred_at": "2026-01-01T12:00:00Z",
        "observed_at": "2026-01-01T12:00:01Z",
        "severity": "info",
        "payload": {},
    }
    assert client.post("/api/v1/events", json=event).status_code == 400


def test_event_rejects_unknown_schema_version() -> None:
    event = {
        "schema_version": "openshield.event.v2",
        "event_id": "event-004",
        "source": {"integration_id": "router-lab", "kind": "openwrt"},
        "event_type": "gateway.health",
        "occurred_at": "2026-01-01T12:00:00Z",
        "observed_at": "2026-01-01T12:00:01Z",
        "severity": "info",
        "payload": {},
    }
    assert client.post("/api/v1/events", json=event).status_code == 422
