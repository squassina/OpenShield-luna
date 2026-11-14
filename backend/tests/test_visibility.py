from datetime import UTC, datetime, timedelta
from uuid import uuid4

from fastapi.testclient import TestClient

from openshield.api.main import app
from openshield.events.models import EventEnvelope, EventSource, Severity
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

    events = client.get("/api/v1/events?integration_id=sensor-suricata&severity=medium").json()["items"]
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
        "nodes": [],
        "node_details": [],
        "edges": [],
        "segments": [],
        "relationships": [],
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
    assert len(filtered.json()["items"]) == 1
    assert filtered.json()["items"][0]["event_type"] == "network.suricata.alert"


def test_sensor_event_ids_are_scoped_to_integration() -> None:
    record = {"timestamp": "2026-01-01T12:00:00Z", "event_type": "alert", "community_id": "same-flow"}
    assert normalize_suricata(record, "sensor-one").event_id != normalize_suricata(record, "sensor-two").event_id


def test_sensor_batch_rejects_non_object_record() -> None:
    import pytest
    with pytest.raises(TypeError, match="JSON object"):
        normalize_sensor_batch("zeek", [None], "sensor")


def _ingest_discovery(
    devices: list[dict[str, object]], observed_at: datetime | None = None
) -> None:
    client.post("/api/v1/gateway/connect", json={
        "protocol_version": "openshield.gateway.v1",
        "gateway_id": "home-gateway",
        "gateway_type": "openwrt",
        "connector_version": "0.1.0",
        "capabilities": ["discover", "health_check"],
    })
    timestamp = observed_at or datetime.now(UTC)
    event = EventEnvelope(
        schema_version="openshield.event.v1",
        event_id=str(uuid4()),
        source=EventSource(integration_id="home-gateway", kind="openwrt"),
        event_type="gateway.discovery",
        occurred_at=timestamp,
        observed_at=timestamp,
        severity=Severity.INFO,
        payload={
            "board": {"model": "OpenWrt test"},
            "interfaces": [{
                "name": "lan",
                "device": "br-lan",
                "vlan_id": 10,
                "subnets": [{
                    "address": "192.0.2.1",
                    "subnet": "192.0.2.0/24",
                    "prefix_length": 24,
                    "ip_version": 4,
                }],
                "gateway_addresses": ["192.0.2.1"],
                "metadata_source": "network.interface.dump",
            }],
            "devices": devices,
            "device_discovery": {"source": "luci-rpc"},
        },
    )
    response = client.post("/api/v1/events", json=event.model_dump(mode="json"))
    assert response.status_code == 202


def _ingest_identity_sensor_event() -> None:
    register_sensor("sensor-zeek", "zeek")
    response = client.post("/api/v1/sensors/sensor-zeek/events", json=[{
        "ts": datetime.now(UTC).timestamp(),
        "_path": "conn",
        "uid": str(uuid4()),
        "id.orig_h": "192.0.2.10",
        "id.orig_p": 53000,
        "id.resp_h": "8.8.8.8",
        "id.resp_p": 443,
        "proto": "tcp",
        "translated_src_ip": "203.0.113.10",
    }])
    assert response.status_code == 202


def _identity_device(mac: str, name: str) -> dict[str, object]:
    return {
        "mac_address": mac,
        "name": name,
        "ip_address": "192.0.2.10",
        "ipv4_addresses": ["192.0.2.10"],
        "ipv6_addresses": [],
        "address_evidence": {
            "192.0.2.10": [{"source": "dhcp_lease", "confidence": "high"}],
        },
        "interface": "lan",
    }


def test_inventory_enriches_sensor_ip_with_identity_and_subnet_provenance() -> None:
    _ingest_identity_sensor_event()
    _ingest_discovery([_identity_device("aa:bb:cc:dd:ee:ff", "workstation")])

    devices = client.get("/api/v1/inventory/devices").json()
    device = next(item for item in devices if item["ip_address"] == "192.0.2.10")
    assert device["identity_status"] == "identified"
    assert device["mac_address"] == "aa:bb:cc:dd:ee:ff"
    assert device["hostname"] == "workstation"
    assert device["identity_sources"] == ["dhcp_lease"]
    assert device["identity_confidence"] == "high"
    assert device["network_segments"][0]["subnet"] == "192.0.2.0/24"
    assert device["network_segments"][0]["vlan_id"] == 10

    topology = client.get("/api/v1/inventory/topology").json()
    connection = next(
        edge for edge in topology["edges"]
        if edge["relationship"] == "connection"
    )
    assert connection["evidence_type"] == "observed"
    assert connection["source_integration_ids"] == ["sensor-zeek"]
    nat = next(
        edge for edge in topology["edges"]
        if edge["relationship"] == "nat_translation"
    )
    assert nat["source"] == "192.0.2.10"
    assert nat["target"] == "203.0.113.10"
    membership = next(
        relation for relation in topology["relationships"]
        if relation["relationship"] == "network_segment_membership"
    )
    assert membership["evidence_type"] == "inferred"
    assert membership["target"] == "192.0.2.0/24"


def test_inventory_reports_conflicting_current_mac_mappings() -> None:
    _ingest_identity_sensor_event()
    _ingest_discovery([
        _identity_device("aa:bb:cc:dd:ee:ff", "device-a"),
        _identity_device("11:22:33:44:55:66", "device-b"),
    ])

    device = next(
        item for item in client.get("/api/v1/inventory/devices").json()
        if item["ip_address"] == "192.0.2.10"
    )
    assert device["identity_status"] == "conflict"
    assert "mac_address" not in device
    assert len(device["identity_candidates"]) == 2


def test_inventory_keeps_stale_identity_without_merging_it() -> None:
    _ingest_identity_sensor_event()
    _ingest_discovery(
        [_identity_device("aa:bb:cc:dd:ee:ff", "workstation")],
        datetime.now(UTC) - timedelta(minutes=2),
    )

    device = next(
        item for item in client.get("/api/v1/inventory/devices").json()
        if item["ip_address"] == "192.0.2.10"
    )
    assert device["identity_status"] == "stale"
    assert "mac_address" not in device
    assert device["identity_candidates"][0]["status"] == "stale"
