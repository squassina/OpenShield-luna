from fastapi.testclient import TestClient

from openshield.api.main import app
from openshield.visibility.normalizers import (
    normalize_sensor_batch,
    normalize_suricata,
    normalize_zeek,
)

client = TestClient(app)


def setup_function() -> None:
    from openshield.api import main
    main.store.reset()


def register_sensor(sensor_id: str, kind: str) -> None:
    response = client.post("/api/v1/integrations", json={
        "integration_id": sensor_id,
        "kind": kind,
        "display_name": f"Test {kind}",
    })
    assert response.status_code == 201


def test_suricata_eve_alert_is_normalized_and_severity_mapped() -> None:
    event = normalize_suricata({
        "timestamp": "2026-01-01T12:00:00Z",
        "event_type": "alert",
        "src_ip": "192.0.2.10",
        "dest_ip": "198.51.100.20",
        "proto": "TCP",
        "flow_id": 123,
        "alert": {"signature": "Test signature", "severity": 1, "token": "must-not-be-retained"},
        "password": "must-not-be-retained",
    }, "sensor-suricata")
    assert event.event_type == "network.suricata.alert"
    assert event.severity.value == "high"
    assert event.payload["signature"] == "Test signature"
    assert "password" not in event.payload
    assert "token" not in event.payload["alert"]
    assert event.source.kind == "suricata"


def test_zeek_connection_is_normalized() -> None:
    event = normalize_zeek({
        "ts": 1767225600.0,
        "_path": "conn",
        "uid": "C123",
        "id.orig_h": "192.0.2.10",
        "id.resp_h": "198.51.100.20",
        "proto": "tcp",
        "service": "https",
        "duration": 1.2,
    }, "sensor-zeek")
    assert event.event_type == "network.zeek.conn"
    assert event.payload["id.orig_h"] == "192.0.2.10"
    assert event.payload["service"] == "https"


def test_sensor_batch_rejects_unknown_types_and_oversized_batches() -> None:
    with __import__("pytest").raises(ValueError, match="Unsupported"):
        normalize_sensor_batch("suricata", [{"timestamp": "2026-01-01T00:00:00Z", "event_type": "unknown"}], "sensor")
    with __import__("pytest").raises(ValueError, match="between 1 and 500"):
        normalize_sensor_batch("zeek", [], "sensor")


def test_suricata_sensor_ingestion_is_idempotent_and_visible() -> None:
    register_sensor("sensor-suricata", "suricata")
    record = {
        "timestamp": "2026-01-01T12:00:00Z",
        "event_type": "alert",
        "src_ip": "192.0.2.10",
        "dest_ip": "198.51.100.20",
        "proto": "TCP",
        "community_id": "flow-abc",
        "alert": {"signature": "Suspicious test", "severity": 2},
    }
    url = "/api/v1/sensors/sensor-suricata/events"
    first = client.post(url, json=[record])
    second = client.post(url, json=[record])
    assert first.status_code == second.status_code == 202
    assert first.json() == {"accepted": 1, "duplicates": 0, "received": 1}
    assert second.json() == {"accepted": 0, "duplicates": 1, "received": 1}

    events = client.get("/api/v1/events?integration_id=sensor-suricata&severity=medium").json()
    assert len(events) == 1
    assert events[0]["event_type"] == "network.suricata.alert"


def test_zeek_sensor_ingestion_populates_inventory_and_topology() -> None:
    register_sensor("sensor-zeek", "zeek")
    record = {
        "ts": 1767225600.0,
        "_path": "conn",
        "uid": "C456",
        "id.orig_h": "192.0.2.11",
        "id.orig_p": 53000,
        "id.resp_h": "8.8.8.8",
        "id.resp_p": 443,
        "proto": "tcp",
        "service": "ssl",
    }
    response = client.post("/api/v1/sensors/sensor-zeek/events", json=[record])
    assert response.status_code == 202
    devices = client.get("/api/v1/inventory/devices").json()
    assert {item["ip_address"] for item in devices} == {"192.0.2.11", "8.8.8.8"}
    scopes = {item["ip_address"]: item["scope"] for item in devices}
    assert scopes == {"192.0.2.11": "private", "8.8.8.8": "public"}
    topology = client.get("/api/v1/inventory/topology").json()
    assert topology["nodes"] == ["192.0.2.11", "8.8.8.8"]
    assert topology["node_details"][0]["ip_version"] == 4
    assert topology["edges"][0]["protocol"] == "tcp"
    assert topology["edges"][0]["direction"] == "outbound"


def test_sensor_health_reports_no_data_then_healthy() -> None:
    register_sensor("sensor-zeek", "zeek")
    assert client.get("/api/v1/sensors").json()[0]["status"] == "no_data"
    client.post("/api/v1/sensors/sensor-zeek/events", json=[{
        "ts": 1767225600.0, "_path": "dns", "uid": "D1",
        "id.orig_h": "192.0.2.15", "query": "example.test",
    }])
    status = client.get("/api/v1/sensors").json()[0]
    assert status["status"] == "healthy"
    assert status["events_seen"] == 1


def test_sensor_endpoint_rejects_non_sensor_integrations() -> None:
    client.post("/api/v1/gateway/connect", json={
        "protocol_version": "openshield.gateway.v1",
        "gateway_id": "home-gateway",
        "gateway_type": "openwrt",
        "connector_version": "0.1.0",
        "capabilities": ["discover", "health_check"],
    })
    assert client.post("/api/v1/sensors/home-gateway/events", json=[{}]).status_code == 404


def test_inventory_ignores_invalid_unspecified_and_multicast_addresses() -> None:
    register_sensor("sensor-suricata", "suricata")
    response = client.post("/api/v1/sensors/sensor-suricata/events", json=[{
        "timestamp": "2026-01-01T12:00:00Z",
        "event_type": "flow",
        "src_ip": "not-an-ip",
        "dest_ip": "224.0.0.1",
        "proto": "UDP",
    }])
    assert response.status_code == 202
    assert client.get("/api/v1/inventory/devices").json() == []
    assert client.get("/api/v1/inventory/topology").json() == {
        "nodes": [], "node_details": [], "edges": []
    }


def test_event_filters_and_limit_are_applied_before_results_are_loaded() -> None:
    register_sensor("sensor-suricata", "suricata")
    for event_type, source_ip in [("alert", "192.0.2.1"), ("flow", "192.0.2.2")]:
        response = client.post("/api/v1/sensors/sensor-suricata/events", json=[{
            "timestamp": "2026-01-01T12:00:00Z",
            "event_type": event_type,
            "src_ip": source_ip,
            "dest_ip": "8.8.8.8",
            "proto": "TCP",
            "alert": {"severity": 1} if event_type == "alert" else {},
        }])
        assert response.status_code == 202
    filtered = client.get(
        "/api/v1/events?integration_id=sensor-suricata&event_type=network.suricata.alert&limit=1"
    )
    assert filtered.status_code == 200
    assert len(filtered.json()) == 1
    assert filtered.json()[0]["event_type"] == "network.suricata.alert"
