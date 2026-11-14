import os
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from openshield.api.main import app
from openshield.core.storage import PostgresStore
from openshield.gateway.registry import GatewayConnectionRegistry
from openshield.integrations.registry import IntegrationRegistry

client = TestClient(app)


def setup_function() -> None:
    from openshield.api import main
    main.store.reset()


def register_integration(integration_id: str = "router-lab") -> None:
    response = client.post("/api/v1/integrations", json={
        "integration_id": integration_id,
        "kind": "openwrt",
        "display_name": "Lab router",
        "config": {"base_url": "https://192.0.2.1"},
    })
    assert response.status_code == 201


def gateway_payload(gateway_id: str = "home-gateway") -> dict[str, object]:
    return {
        "protocol_version": "openshield.gateway.v1",
        "gateway_id": gateway_id,
        "gateway_type": "openwrt",
        "connector_version": "0.1.0",
        "capabilities": ["discover", "health_check"],
    }


def sample_event(event_id: str = "event-001", integration_id: str = "router-lab") -> dict[str, object]:
    return {
        "schema_version": "openshield.event.v1",
        "event_id": event_id,
        "source": {"integration_id": integration_id, "kind": "openwrt"},
        "event_type": "gateway.health",
        "occurred_at": "2026-01-01T12:00:00Z",
        "observed_at": "2026-01-01T12:00:01Z",
        "severity": "info",
        "payload": {"status": "reachable"},
    }


def test_health_endpoints_are_public_and_readiness_checks_database() -> None:
    assert client.get("/health/live").json() == {"status": "alive"}
    assert client.get("/health/ready").json() == {"status": "ready"}


def test_api_endpoints_are_available_without_authentication() -> None:
    assert client.get("/api/v1/integrations").status_code == 200
    assert client.get("/api/v1/events").status_code == 200
    assert client.get("/api/v1/gateways").status_code == 200
    assert client.get("/api/v1/audit").status_code == 200
    assert client.get("/metrics").status_code == 200


def test_register_openwrt_and_probe_without_authentication() -> None:
    register_integration()
    response = client.get("/api/v1/integrations/router-lab/probe")
    assert response.status_code == 200
    assert response.json()["transport"] == "gateway_connector"
    assert response.json()["capabilities"] == ["health_check", "discover"]


def test_integration_can_be_updated_without_changing_identity_or_kind() -> None:
    register_integration()
    response = client.patch("/api/v1/integrations/router-lab", json={
        "display_name": "Updated router",
        "config": {"base_url": "http://192.0.2.2"},
    })
    assert response.status_code == 200
    assert response.json()["integration_id"] == "router-lab"
    assert response.json()["kind"] == "openwrt"
    assert response.json()["display_name"] == "Updated router"
    assert response.json()["config"]["base_url"] == "http://192.0.2.2"


def test_integration_update_rejects_secrets() -> None:
    register_integration()
    response = client.patch("/api/v1/integrations/router-lab", json={
        "config": {"password": "must-not-be-stored"},
    })
    assert response.status_code == 422


def test_integration_can_be_deleted_without_deleting_event_history() -> None:
    register_integration()
    assert client.post("/api/v1/events", json=sample_event()).status_code == 202
    response = client.delete("/api/v1/integrations/router-lab")
    assert response.status_code == 204
    assert client.get("/api/v1/integrations/router-lab/probe").status_code == 404
    assert len(client.get("/api/v1/events").json()["items"]) == 1
    actions = [item["action"] for item in client.get("/api/v1/audit").json()]
    assert "integration.deleted" in actions


def test_update_and_delete_unknown_integration_return_404() -> None:
    assert client.patch("/api/v1/integrations/missing", json={"display_name": "Missing"}).status_code == 404
    assert client.delete("/api/v1/integrations/missing").status_code == 404


def test_duplicate_integration_is_rejected() -> None:
    register_integration()
    response = client.post("/api/v1/integrations", json={
        "integration_id": "router-lab", "kind": "openwrt", "display_name": "Duplicate",
    })
    assert response.status_code == 409


def test_unknown_integration_kind_is_rejected() -> None:
    response = client.post("/api/v1/integrations", json={
        "integration_id": "unknown-lab", "kind": "unknown", "display_name": "Unknown",
    })
    assert response.status_code == 400


def test_gateway_connect_automatically_registers_home_gateway() -> None:
    response = client.post("/api/v1/gateway/connect", json=gateway_payload())
    assert response.status_code == 201
    assert response.json()["status"] == "connected"
    integrations = client.get("/api/v1/integrations").json()
    assert len(integrations) == 1
    assert integrations[0]["integration_id"] == "home-gateway"
    assert integrations[0]["kind"] == "openwrt"
    assert client.get("/api/v1/gateways").json()[0]["status"] == "connected"


def test_gateway_heartbeat_identifies_gateway_without_credentials() -> None:
    client.post("/api/v1/gateway/connect", json=gateway_payload())
    response = client.post("/api/v1/gateway/heartbeat", json={
        "protocol_version": "openshield.gateway.v1", "gateway_id": "home-gateway",
    })
    assert response.status_code == 200
    assert response.json()["status"] == "acknowledged"


def test_gateway_heartbeat_requires_existing_connection() -> None:
    response = client.post("/api/v1/gateway/heartbeat", json={
        "protocol_version": "openshield.gateway.v1", "gateway_id": "unknown-gateway",
    })
    assert response.status_code == 409


def test_gateway_cannot_advertise_enforcement_capabilities() -> None:
    payload = gateway_payload()
    payload["capabilities"] = ["execute_action"]
    assert client.post("/api/v1/gateway/connect", json=payload).status_code == 422


def test_gateway_rejects_unsupported_type() -> None:
    register_integration("home-gateway")
    payload = gateway_payload()
    payload["gateway_type"] = "other"
    assert client.post("/api/v1/gateway/connect", json=payload).status_code == 422


def test_ingest_event_preserves_source_provenance() -> None:
    register_integration()
    assert client.post("/api/v1/events", json=sample_event()).status_code == 202
    stored = client.get("/api/v1/events").json()["items"]
    assert stored[0]["source"]["integration_id"] == "router-lab"


def test_router_device_inventory_uses_mac_identity_and_tracks_presence() -> None:
    client.post("/api/v1/gateway/connect", json=gateway_payload())
    old_seen = datetime.now(UTC) - timedelta(seconds=120)
    event = sample_event("discovery-old", integration_id="home-gateway")
    event["event_type"] = "gateway.discovery"
    event["observed_at"] = old_seen.isoformat()
    event["payload"] = {
        "board": {"hostname": "router"},
        "interfaces": [{"name": "lan", "device": "br-lan", "up": True}],
        "devices": [{
            "mac_address": "aa:bb:cc:dd:ee:ff", "name": "desktop",
            "ip_address": "192.0.2.10", "ipv4_addresses": ["192.0.2.10"],
            "ipv6_addresses": [], "device": "br-lan", "interface": "lan", "source": "luci-rpc",
        }, {
            "mac_address": "11:22:33:44:55:66", "name": "ipv6-only",
            "ip_address": "", "ipv4_addresses": [], "ipv6_addresses": ["2001:db8::20"],
            "device": "", "interface": "Unmapped", "source": "luci-rpc",
        }],
    }
    assert client.post("/api/v1/events", json=event).status_code == 202
    first = client.get("/api/v1/inventory/router-devices").json()
    assert first["gateways"][0]["board"]["hostname"] == "router"
    assert {item["mac_address"] for item in first["devices"]} == {"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"}
    assert next(item for item in first["devices"] if item["mac_address"] == "aa:bb:cc:dd:ee:ff")["status"] == "offline"
    assert next(item for item in first["devices"] if item["mac_address"] == "11:22:33:44:55:66")["ipv6_addresses"] == ["2001:db8::20"]

    event["event_id"] = "discovery-new"
    event["observed_at"] = datetime.now(UTC).isoformat()
    event["payload"]["devices"][0]["ip_address"] = "192.0.2.20"
    event["payload"]["devices"][0]["ipv4_addresses"] = ["192.0.2.20"]
    assert client.post("/api/v1/events", json=event).status_code == 202
    current = client.get("/api/v1/inventory/router-devices").json()["devices"]
    desktop = next(item for item in current if item["mac_address"] == "aa:bb:cc:dd:ee:ff")
    assert len(current) == 2
    assert desktop["ip_address"] == "192.0.2.20"
    assert desktop["status"] == "online"
    assert desktop["first_seen"] == old_seen.isoformat()

def test_event_from_unknown_source_is_rejected() -> None:
    assert client.post("/api/v1/events", json=sample_event()).status_code == 400


def test_event_source_kind_must_match_registered_integration() -> None:
    register_integration()
    event = sample_event()
    event["source"] = {"integration_id": "router-lab", "kind": "other"}
    assert client.post("/api/v1/events", json=event).status_code == 400


def test_event_rejects_unknown_schema_version() -> None:
    event = sample_event()
    event["schema_version"] = "openshield.event.v2"
    assert client.post("/api/v1/events", json=event).status_code == 422


def test_integration_registration_rejects_secrets_in_config() -> None:
    response = client.post("/api/v1/integrations", json={
        "integration_id": "router-secret", "kind": "openwrt", "display_name": "Router",
        "config": {"base_url": "http://192.0.2.1", "password": "must-not-be-stored"},
    })
    assert response.status_code == 422


def test_persisted_state_survives_store_recreation() -> None:
    client.post("/api/v1/gateway/connect", json=gateway_payload())
    assert client.post("/api/v1/events", json=sample_event(integration_id="home-gateway")).status_code == 202
    restarted_store = PostgresStore(os.environ["OPENSHIELD_DATABASE_URL"])
    assert IntegrationRegistry(restarted_store).get("home-gateway") is not None
    assert len(restarted_store.list_events()) == 1
    assert GatewayConnectionRegistry(restarted_store).get_status("home-gateway")["status"] == "connected"


def test_duplicate_event_id_is_acknowledged_idempotently() -> None:
    register_integration()
    event = sample_event()
    first = client.post("/api/v1/events", json=event)
    duplicate = client.post("/api/v1/events", json=event)
    assert first.status_code == duplicate.status_code == 202
    assert first.json()["status"] == "accepted"
    assert duplicate.json()["status"] == "duplicate"


def test_audit_records_registration_connection_and_event_ingestion() -> None:
    client.post("/api/v1/gateway/connect", json=gateway_payload())
    assert client.post("/api/v1/events", json=sample_event(integration_id="home-gateway")).status_code == 202
    records = client.get("/api/v1/audit").json()
    assert [record["action"] for record in records[:3]] == [
        "event.ingested", "gateway.connected", "integration.registered",
    ]
    assert all(record["actor_id"] is None for record in records[:3])


def test_audit_limit_is_bounded() -> None:
    assert client.get("/api/v1/audit?limit=501").status_code == 422


def test_metrics_endpoint_exposes_prometheus_counters() -> None:
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
    assert "openshield_http_requests_total" in response.text



def test_dashboard_is_served_from_node_root() -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "DNS privacy intelligence" in response.text
    assert "Sync lists" in response.text


def test_integration_can_be_disabled_and_reenabled() -> None:
    register_integration()
    response = client.patch("/api/v1/integrations/router-lab", json={"enabled": False})
    assert response.status_code == 200
    assert response.json()["enabled"] is False
    response = client.patch("/api/v1/integrations/router-lab", json={"enabled": True})
    assert response.status_code == 200
    assert response.json()["enabled"] is True


def test_event_cursor_pagination_returns_no_duplicates() -> None:
    register_integration()
    for index in range(4):
        event = sample_event(event_id=f"page-{index}")
        event["occurred_at"] = f"2026-01-01T12:00:0{index}Z"
        event["observed_at"] = f"2026-01-01T12:00:0{index}Z"
        assert client.post("/api/v1/events", json=event).status_code == 202
    first = client.get("/api/v1/events?limit=2").json()
    assert len(first["items"]) == 2 and first["next_cursor"]
    second = client.get("/api/v1/events?limit=2&cursor="+first["next_cursor"]).json()
    ids = [item["event_id"] for item in first["items"] + second["items"]]
    assert len(ids) == len(set(ids)) == 4
    assert second["next_cursor"] is None


def test_event_endpoint_rejects_invalid_cursor() -> None:
    assert client.get("/api/v1/events?cursor=invalid").status_code == 422


def test_disabled_sensor_rejects_ingestion() -> None:
    response = client.post("/api/v1/integrations", json={
        "integration_id": "sensor-disabled", "kind": "zeek", "display_name": "Disabled sensor",
    })
    assert response.status_code == 201
    assert client.patch("/api/v1/integrations/sensor-disabled", json={"enabled": False}).status_code == 200
    assert client.post("/api/v1/sensors/sensor-disabled/events", json=[{}]).status_code == 404


def test_event_retention_deletes_only_events_before_cutoff_in_bounded_batches() -> None:
    from openshield.api import main
    register_integration()
    assert client.post("/api/v1/events", json=sample_event("retention-old")).status_code == 202
    deleted = main.store.purge_events_before(
        datetime.now(UTC) + timedelta(seconds=1), batch_size=1
    )
    assert deleted == 1
    assert client.get("/api/v1/events").json()["items"] == []


def test_openwrt_credentials_are_encrypted_and_only_released_to_gateway(monkeypatch) -> None:
    from cryptography.fernet import Fernet

    monkeypatch.setenv("OPENSHIELD_SECRET_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("OPENSHIELD_GATEWAY_TOKEN", "connector-test-token")
    register_integration("home-gateway")
    response = client.put(
        "/api/v1/integrations/home-gateway/openwrt-credentials",
        json={
            "base_url": "https://192.0.2.1", "username": "rpc-user",
            "password": "router-secret-value",
        },
    )
    assert response.status_code == 200
    assert "router-secret-value" not in response.text
    integration = client.get("/api/v1/integrations").json()[0]
    assert integration["config"]["rpc_configured"] is True
    assert "password" not in str(integration)
    from openshield.api import main
    encrypted = main.store.get_integration_secret("home-gateway")
    assert encrypted and b"router-secret-value" not in encrypted
    config = client.get(
        "/api/v1/gateway/config/home-gateway",
        headers={"Authorization": "Bearer connector-test-token"},
    )
    assert config.status_code == 200
    assert config.json()["openwrt_config"]["password"] == "router-secret-value"
    assert client.get("/api/v1/gateway/config/home-gateway").status_code == 401


def test_openwrt_credentials_require_secret_key_and_validate_url(monkeypatch) -> None:
    register_integration("home-gateway")
    monkeypatch.delenv("OPENSHIELD_SECRET_KEY", raising=False)
    missing_key = client.put(
        "/api/v1/integrations/home-gateway/openwrt-credentials",
        json={"base_url": "https://192.0.2.1", "username": "rpc", "password": "secret"},
    )
    assert missing_key.status_code == 503
    monkeypatch.setenv("OPENSHIELD_GATEWAY_TOKEN", "connector-test-token")
    invalid_url = client.put(
        "/api/v1/integrations/home-gateway/openwrt-credentials",
        json={"base_url": "https://user:pass@192.0.2.1", "username": "rpc", "password": "secret"},
    )
    assert invalid_url.status_code == 422


def test_api_basic_auth_and_csrf_protection(monkeypatch) -> None:
    import base64

    monkeypatch.setenv("OPENSHIELD_API_AUTH_ENABLED", "true")
    monkeypatch.setenv("OPENSHIELD_API_USERNAME", "admin")
    monkeypatch.setenv("OPENSHIELD_API_PASSWORD", "strong-test-password")
    assert client.get("/api/v1/integrations").status_code == 401
    credentials = base64.b64encode(b"admin:strong-test-password").decode()
    headers = {"Authorization": "Basic " + credentials}
    assert client.get("/api/v1/integrations", headers=headers).status_code == 200
    assert client.post(
        "/api/v1/integrations",
        headers={**headers, "Origin": "https://attacker.example"},
        json={"integration_id":"bad-origin","kind":"openwrt","display_name":"Bad"},
    ).status_code == 403
    assert client.post(
        "/api/v1/integrations",
        headers={**headers, "Sec-Fetch-Site":"cross-site"},
        json={"integration_id":"bad-fetch-site","kind":"openwrt","display_name":"Bad fetch site"},
    ).status_code == 403
    assert client.post(
        "/api/v1/integrations",
        headers=headers,
        json={"integration_id":"good-origin","kind":"openwrt","display_name":"Good"},
    ).status_code == 201
    monkeypatch.setenv("OPENSHIELD_API_AUTH_ENABLED", "false")


def test_gateway_token_is_required_when_configured(monkeypatch) -> None:
    monkeypatch.setenv("OPENSHIELD_GATEWAY_TOKEN", "connector-test-token")
    assert client.post("/api/v1/gateway/connect", json=gateway_payload()).status_code == 401
    response = client.post(
        "/api/v1/gateway/connect", json=gateway_payload(),
        headers={"Authorization": "Bearer connector-test-token"},
    )
    assert response.status_code == 201


def test_openwrt_secret_rotation_reencrypts_with_active_key(monkeypatch) -> None:
    from cryptography.fernet import Fernet

    from openshield.core.secrets import SecretStore

    old_key = Fernet.generate_key().decode()
    new_key = Fernet.generate_key().decode()
    monkeypatch.setenv("OPENSHIELD_SECRET_KEY", old_key)
    register_integration("home-gateway")
    SecretStore(__import__("openshield.api.main", fromlist=["store"]).store).set(
        "home-gateway", {"username": "rpc", "password": "rotate-me"},
    )
    monkeypatch.setenv("OPENSHIELD_SECRET_KEY", new_key)
    monkeypatch.setenv("OPENSHIELD_SECRET_KEY_PREVIOUS", old_key)
    from openshield.api import main
    rotated = SecretStore(main.store).get("home-gateway")
    assert rotated == {"username": "rpc", "password": "rotate-me"}
    encrypted = main.store.get_integration_secret("home-gateway")
    assert encrypted and Fernet(new_key.encode()).decrypt(encrypted)


def test_admin_auth_rate_limits_repeated_failures(monkeypatch) -> None:
    import base64

    from openshield.api import main

    monkeypatch.setenv("OPENSHIELD_API_AUTH_ENABLED", "true")
    monkeypatch.setenv("OPENSHIELD_API_USERNAME", "admin")
    monkeypatch.setenv("OPENSHIELD_API_PASSWORD", "strong-test-password")
    monkeypatch.setattr(main.time, "monotonic", lambda: 12345.0)
    bad = {"Authorization": "Basic " + base64.b64encode(b"admin:wrong").decode()}
    for _ in range(5):
        assert client.get("/api/v1/integrations", headers=bad).status_code == 401
    assert client.get("/api/v1/integrations", headers=bad).status_code == 429
    monkeypatch.setenv("OPENSHIELD_API_AUTH_ENABLED", "false")


def test_openwrt_credentials_can_be_rotated_and_revoked(monkeypatch) -> None:
    from cryptography.fernet import Fernet

    monkeypatch.setenv("OPENSHIELD_SECRET_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("OPENSHIELD_GATEWAY_TOKEN", "connector-test-token")
    register_integration("home-gateway")
    endpoint = "/api/v1/integrations/home-gateway/openwrt-credentials"
    payload = {"base_url": "https://192.0.2.1", "username": "rpc", "password": "first-secret"}
    assert client.put(endpoint, json=payload).status_code == 200
    payload["password"] = "rotated-secret"
    assert client.put(endpoint, json=payload).status_code == 200
    from openshield.api import main
    from openshield.core.secrets import SecretStore
    assert SecretStore(main.store).get("home-gateway")["password"] == "rotated-secret"
    assert client.delete(endpoint).status_code == 204
    assert main.store.get_integration_secret("home-gateway") is None
    assert client.get("/api/v1/integrations").json()[0]["config"]["rpc_configured"] is False


def test_openwrt_test_endpoint_distinguishes_missing_connector(monkeypatch) -> None:
    from cryptography.fernet import Fernet

    monkeypatch.setenv("OPENSHIELD_SECRET_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("OPENSHIELD_GATEWAY_TOKEN", "connector-test-token")
    register_integration("home-gateway")
    response = client.put(
        "/api/v1/integrations/home-gateway/openwrt-credentials",
        json={"base_url": "https://192.0.2.1", "username": "rpc", "password": "secret"},
    )
    assert response.status_code == 200
    check = client.get("/api/v1/integrations/home-gateway/test")
    assert check.status_code == 200
    assert check.json()["status"] == "connector_disconnected"


def test_openwrt_status_includes_recent_discovery_and_rpc_freshness(monkeypatch) -> None:
    from cryptography.fernet import Fernet
    monkeypatch.setenv("OPENSHIELD_SECRET_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("OPENSHIELD_GATEWAY_TOKEN", "connector-test-token")
    register_integration("home-gateway")
    headers = {"Authorization": "Bearer connector-test-token"}
    connected = client.post("/api/v1/gateway/connect", json=gateway_payload(), headers=headers)
    assert connected.status_code == 201
    now = datetime.now(UTC)
    health = sample_event("router-health", "home-gateway")
    health["event_type"] = "gateway.health"
    health["observed_at"] = now.isoformat()
    health["occurred_at"] = now.isoformat()
    health["payload"] = {"status": "reachable"}
    assert client.post("/api/v1/events", json=health, headers=headers).status_code == 202
    discovery = sample_event("router-discovery", "home-gateway")
    discovery["event_type"] = "gateway.discovery"
    discovery["observed_at"] = now.isoformat()
    discovery["occurred_at"] = now.isoformat()
    discovery["payload"] = {
        "board": {"hostname": "router", "model": "OpenWrt test", "release": {"version": "24.10"}},
        "interfaces": [{"name": "lan", "up": True, "ipv4_address": ["192.0.2.1"]}],
    }
    assert client.post("/api/v1/events", json=discovery, headers=headers).status_code == 202
    from openshield.api import main
    main.SecretStore(main.store).set("home-gateway", {"base_url":"https://192.0.2.1","username":"rpc","password":"secret"})
    from openshield.integrations.models import IntegrationUpdate
    main.registry.update("home-gateway", IntegrationUpdate(config={"base_url":"https://192.0.2.1","rpc_configured":True}))
    response = client.get("/api/v1/integrations/home-gateway/test")
    assert response.status_code == 200
    assert response.json()["status"] == "router_rpc_connected"
    assert response.json()["router"]["board"]["model"] == "OpenWrt test"
    assert response.json()["router"]["interfaces"][0]["name"] == "lan"
    assert response.json()["last_rpc_check_age_seconds"] <= 90


def test_openwrt_status_marks_old_rpc_check_as_stale(monkeypatch) -> None:
    from cryptography.fernet import Fernet
    monkeypatch.setenv("OPENSHIELD_SECRET_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("OPENSHIELD_GATEWAY_TOKEN", "connector-test-token")
    register_integration("home-gateway")
    assert client.put(
        "/api/v1/integrations/home-gateway/openwrt-credentials",
        json={"base_url":"https://192.0.2.1","username":"rpc","password":"secret"},
    ).status_code == 200
    headers={"Authorization":"Bearer connector-test-token"}
    assert client.post("/api/v1/gateway/connect",json=gateway_payload(),headers=headers).status_code==201
    old=sample_event("old-router-health","home-gateway")
    old["event_type"]="gateway.health"
    old["observed_at"]=(datetime.now(UTC)-timedelta(minutes=5)).isoformat()
    old["occurred_at"]=old["observed_at"]
    old["payload"]={"status":"reachable"}
    assert client.post("/api/v1/events",json=old,headers=headers).status_code==202
    response=client.get("/api/v1/integrations/home-gateway/test")
    assert response.status_code==200
    assert response.json()["status"]=="router_rpc_stale"


def test_opnsense_credentials_are_encrypted_and_diagnostics_are_read_only(monkeypatch) -> None:
    from cryptography.fernet import Fernet

    from openshield.api import main
    from openshield.core.secrets import SecretStore

    monkeypatch.setenv("OPENSHIELD_SECRET_KEY", Fernet.generate_key().decode())
    registered = client.post("/api/v1/integrations", json={
        "integration_id": "opnsense-home",
        "kind": "opnsense",
        "display_name": "Home firewall",
        "config": {"base_url": "https://192.0.2.1"},
    })
    assert registered.status_code == 201

    saved = client.put("/api/v1/integrations/opnsense-home/opnsense-credentials", json={
        "base_url": "https://192.0.2.1",
        "api_key": "test-api-key",
        "api_secret": "sensitive-api-secret",
    })
    assert saved.status_code == 200
    assert "sensitive-api-secret" not in saved.text
    integration = client.get("/api/v1/integrations").json()[0]
    assert integration["config"]["auth_configured"] is True
    assert "api_secret" not in str(integration)
    encrypted = main.store.get_integration_secret("opnsense-home")
    assert encrypted and b"sensitive-api-secret" not in encrypted
    assert SecretStore(main.store).get("opnsense-home") == {
        "base_url": "https://192.0.2.1",
        "api_key": "test-api-key",
        "api_secret": "sensitive-api-secret",
    }

    class FakeOPNsenseClient:
        def __init__(self, base_url, api_key, api_secret):
            assert base_url == "https://192.0.2.1"
            assert api_key == "test-api-key"
            assert api_secret == "sensitive-api-secret"

        def diagnostics(self):
            return {
                "system": {"hostname": "firewall"},
                "firewall": {"states": 12},
                "arp": {"rows": []},
            }

    monkeypatch.setattr(main, "OPNsenseClient", FakeOPNsenseClient)
    diagnostics = client.get("/api/v1/integrations/opnsense-home/opnsense-diagnostics")
    assert diagnostics.status_code == 200
    assert diagnostics.json()["status"] == "connected"
    assert diagnostics.json()["system"]["hostname"] == "firewall"

    assert client.delete("/api/v1/integrations/opnsense-home/opnsense-credentials").status_code == 204
    assert client.get("/api/v1/integrations/opnsense-home/opnsense-diagnostics").status_code == 409
    assert client.get("/api/v1/integrations").json()[0]["config"]["auth_configured"] is False


def test_pfsense_credentials_are_encrypted_and_diagnostics_are_read_only(monkeypatch) -> None:
    from cryptography.fernet import Fernet

    from openshield.api import main
    from openshield.core.secrets import SecretStore

    monkeypatch.setenv("OPENSHIELD_SECRET_KEY", Fernet.generate_key().decode())
    registered = client.post("/api/v1/integrations", json={
        "integration_id": "pfsense-home",
        "kind": "pfsense",
        "display_name": "Home pfSense CE",
        "config": {"base_url": "https://192.0.2.2"},
    })
    assert registered.status_code == 201

    saved = client.put("/api/v1/integrations/pfsense-home/pfsense-credentials", json={
        "base_url": "https://192.0.2.2",
        "api_key": "sensitive-pfsense-api-key",
    })
    assert saved.status_code == 200
    assert "sensitive-pfsense-api-key" not in saved.text
    integration = next(
        item for item in client.get("/api/v1/integrations").json()
        if item["integration_id"] == "pfsense-home"
    )
    assert integration["config"]["auth_configured"] is True
    assert "api_key" not in str(integration)
    encrypted = main.store.get_integration_secret("pfsense-home")
    assert encrypted and b"sensitive-pfsense-api-key" not in encrypted
    assert SecretStore(main.store).get("pfsense-home") == {
        "base_url": "https://192.0.2.2",
        "api_key": "sensitive-pfsense-api-key",
    }

    class FakePfSenseClient:
        def __init__(self, base_url, api_key):
            assert base_url == "https://192.0.2.2"
            assert api_key == "sensitive-pfsense-api-key"

        def diagnostics(self):
            return {
                "system": {"hostname": "pfsense"},
                "interfaces": [{"name": "wan", "status": "up"}],
                "arp": {"data": []},
                "dhcp_leases": {"data": []},
                "gateways": {"data": []},
            }

        def get(self, path):
            assert path == "/api/v2/status/system"
            return {"hostname": "pfsense"}

    monkeypatch.setattr(main, "PfSenseClient", FakePfSenseClient)
    diagnostics = client.get("/api/v1/integrations/pfsense-home/pfsense-diagnostics")
    assert diagnostics.status_code == 200
    assert diagnostics.json()["status"] == "connected"
    assert diagnostics.json()["system"]["hostname"] == "pfsense"
    connection = client.post("/api/v1/integrations/pfsense-home/test")
    assert connection.status_code == 200
    assert connection.json()["provider"] == "pfsense"
    assert connection.json()["imported"] == 0

    assert client.delete("/api/v1/integrations/pfsense-home/pfsense-credentials").status_code == 204
    assert client.get("/api/v1/integrations/pfsense-home/pfsense-diagnostics").status_code == 409
    integration = next(
        item for item in client.get("/api/v1/integrations").json()
        if item["integration_id"] == "pfsense-home"
    )
    assert integration["config"]["auth_configured"] is False



def test_crowdsec_credentials_are_encrypted_and_diagnostics_are_read_only(monkeypatch) -> None:
    from cryptography.fernet import Fernet

    from openshield.api import main
    from openshield.core.secrets import SecretStore

    monkeypatch.setenv("OPENSHIELD_SECRET_KEY", Fernet.generate_key().decode())
    registered = client.post("/api/v1/integrations", json={
        "integration_id": "crowdsec-home",
        "kind": "crowdsec",
        "display_name": "Home CrowdSec",
        "config": {"base_url": "https://192.0.2.20:8080"},
    })
    assert registered.status_code == 201

    credentials = {
        "base_url": "https://192.0.2.20:8080",
        "bouncer_api_key": "sensitive-bouncer-key",
        "machine_id": "openshield-reader",
        "machine_password": "sensitive-machine-password",
    }
    saved = client.put(
        "/api/v1/integrations/crowdsec-home/crowdsec-credentials",
        json=credentials,
    )
    assert saved.status_code == 200
    assert "sensitive-bouncer-key" not in saved.text
    assert "sensitive-machine-password" not in saved.text
    integration = next(
        item for item in client.get("/api/v1/integrations").json()
        if item["integration_id"] == "crowdsec-home"
    )
    assert integration["config"]["auth_configured"] is True
    assert integration["config"]["alerts_auth_configured"] is True
    assert "bouncer_api_key" not in str(integration)
    encrypted = main.store.get_integration_secret("crowdsec-home")
    assert encrypted
    assert b"sensitive-bouncer-key" not in encrypted
    assert b"sensitive-machine-password" not in encrypted
    assert SecretStore(main.store).get("crowdsec-home") == {
        "base_url": "https://192.0.2.20:8080",
        "bouncer_api_key": "sensitive-bouncer-key",
        "machine_id": "openshield-reader",
        "machine_password": "sensitive-machine-password",
    }

    class FakeCrowdSecClient:
        def __init__(self, base_url, bouncer_api_key, machine_id, machine_password):
            assert base_url == "https://192.0.2.20:8080"
            assert bouncer_api_key == "sensitive-bouncer-key"
            assert machine_id == "openshield-reader"
            assert machine_password == "sensitive-machine-password"

        def diagnostics(self):
            return {
                "alerts": [{"id": 1, "scenario": "ssh-bf"}],
                "decisions": [{"type": "ban", "value": "192.0.2.10"}],
                "summary": {
                    "alerts_available": 1,
                    "decisions_available": 1,
                    "alerts_auth_configured": True,
                },
            }

    monkeypatch.setattr(main, "CrowdSecClient", FakeCrowdSecClient)
    diagnostics = client.get(
        "/api/v1/integrations/crowdsec-home/crowdsec-diagnostics"
    )
    assert diagnostics.status_code == 200
    assert diagnostics.headers["cache-control"] == "no-store"
    assert diagnostics.json()["summary"]["alerts_available"] == 1
    assert diagnostics.json()["decisions"][0]["type"] == "ban"

    connection = client.post("/api/v1/integrations/crowdsec-home/test")
    assert connection.status_code == 200
    assert connection.json()["provider"] == "crowdsec"
    assert connection.json()["decisions_available"] == 1
    assert connection.json()["imported"] == 0

    assert client.delete(
        "/api/v1/integrations/crowdsec-home/crowdsec-credentials"
    ).status_code == 204
    assert client.get(
        "/api/v1/integrations/crowdsec-home/crowdsec-diagnostics"
    ).status_code == 409
    integration = next(
        item for item in client.get("/api/v1/integrations").json()
        if item["integration_id"] == "crowdsec-home"
    )
    assert integration["config"]["auth_configured"] is False
    assert integration["config"]["alerts_auth_configured"] is False


def test_crowdsec_requires_machine_id_and_password_together(monkeypatch) -> None:
    from cryptography.fernet import Fernet

    monkeypatch.setenv("OPENSHIELD_SECRET_KEY", Fernet.generate_key().decode())
    client.post("/api/v1/integrations", json={
        "integration_id": "crowdsec-home",
        "kind": "crowdsec",
        "display_name": "Home CrowdSec",
    })
    response = client.put(
        "/api/v1/integrations/crowdsec-home/crowdsec-credentials",
        json={
            "base_url": "https://192.0.2.20:8080",
            "bouncer_api_key": "bouncer-key",
            "machine_id": "machine-only",
        },
    )
    assert response.status_code == 422



def test_wazuh_credentials_are_encrypted_and_diagnostics_are_read_only(monkeypatch) -> None:
    from cryptography.fernet import Fernet

    from openshield.api import main
    from openshield.core.secrets import SecretStore

    monkeypatch.setenv("OPENSHIELD_SECRET_KEY", Fernet.generate_key().decode())
    registered = client.post("/api/v1/integrations", json={
        "integration_id": "wazuh-home",
        "kind": "wazuh",
        "display_name": "Home Wazuh manager",
        "config": {"base_url": "https://192.0.2.30:55000"},
    })
    assert registered.status_code == 201

    credentials = {
        "base_url": "https://192.0.2.30:55000",
        "username": "openshield-reader",
        "password": "sensitive-wazuh-password",
    }
    saved = client.put(
        "/api/v1/integrations/wazuh-home/wazuh-credentials",
        json=credentials,
    )
    assert saved.status_code == 200
    assert "sensitive-wazuh-password" not in saved.text
    integration = next(
        item for item in client.get("/api/v1/integrations").json()
        if item["integration_id"] == "wazuh-home"
    )
    assert integration["config"]["auth_configured"] is True
    assert "username" not in str(integration)
    assert "password" not in str(integration)
    encrypted = main.store.get_integration_secret("wazuh-home")
    assert encrypted
    assert b"sensitive-wazuh-password" not in encrypted
    assert SecretStore(main.store).get("wazuh-home") == credentials

    class FakeWazuhClient:
        def __init__(self, base_url, username, password):
            assert base_url == "https://192.0.2.30:55000"
            assert username == "openshield-reader"
            assert password == "sensitive-wazuh-password"

        def diagnostics(self):
            return {
                "api": {"data": {"api_version": "4.14.0"}, "error": 0},
                "manager_info": {"data": {"affected_items": [{"version": "4.14.0"}]}, "error": 0},
                "manager_status": {
                    "data": {"affected_items": [{"wazuh-analysisd": "running"}]},
                    "error": 0,
                },
                "agents": {
                    "data": {
                        "affected_items": [{"id": "001", "status": "active"}],
                        "total_affected_items": 1,
                    },
                    "error": 0,
                },
                "summary": {
                    "agents_available": 1,
                    "agents_returned": 1,
                    "agents_limit": 500,
                },
            }

    monkeypatch.setattr(main, "WazuhClient", FakeWazuhClient)
    diagnostics = client.get("/api/v1/integrations/wazuh-home/wazuh-diagnostics")
    assert diagnostics.status_code == 200
    assert diagnostics.headers["cache-control"] == "no-store"
    assert diagnostics.json()["summary"]["agents_available"] == 1
    assert diagnostics.json()["agents"]["data"]["affected_items"][0]["id"] == "001"

    connection = client.post("/api/v1/integrations/wazuh-home/test")
    assert connection.status_code == 200
    assert connection.json()["provider"] == "wazuh"
    assert connection.json()["agents_available"] == 1
    assert connection.json()["imported"] == 0

    probe = client.get("/api/v1/integrations/wazuh-home/probe")
    assert probe.status_code == 200
    assert probe.json()["status"] == "configured"

    assert client.delete(
        "/api/v1/integrations/wazuh-home/wazuh-credentials"
    ).status_code == 204
    assert client.get(
        "/api/v1/integrations/wazuh-home/wazuh-diagnostics"
    ).status_code == 409
    integration = next(
        item for item in client.get("/api/v1/integrations").json()
        if item["integration_id"] == "wazuh-home"
    )
    assert integration["config"]["auth_configured"] is False


def test_misp_credentials_are_encrypted_and_sync_indicators(monkeypatch):
    from cryptography.fernet import Fernet
    from openshield.api import main

    monkeypatch.setenv("OPENSHIELD_SECRET_KEY", Fernet.generate_key().decode())
    created = client.post("/api/v1/integrations", json={
        "integration_id": "misp-lab",
        "kind": "misp",
        "display_name": "MISP lab",
        "config": {"base_url": "https://misp.example"},
    })
    assert created.status_code == 201
    credentials = client.put("/api/v1/integrations/misp-lab/misp-credentials", json={
        "base_url": "https://misp.example",
        "api_key": "misp-secret-value",
    })
    assert credentials.status_code == 200
    assert credentials.json()["secret_storage"] == "encrypted"
    assert "misp-secret-value" not in credentials.text
    encrypted = main.store.get_integration_secret("misp-lab")
    assert encrypted and b"misp-secret-value" not in encrypted

    indicators = [{
        "indicator_id": "misp-uuid-1",
        "indicator_type": "ip-src",
        "value": "198.51.100.23",
        "category": "Network activity",
        "event_id": "misp-event-42",
        "comment": "test indicator",
        "to_ids": True,
        "source_timestamp": "1760000000",
    }]
    monkeypatch.setattr(main.MispClient, "search_indicators", lambda self, limit: indicators)
    synced = client.post("/api/v1/integrations/misp-lab/misp-sync?limit=50")
    assert synced.status_code == 200
    assert synced.json()["stored"] == 1
    assert client.get("/api/v1/threat-intel/indicators").json()["count"] == 1

    sensor = client.post("/api/v1/integrations", json={
        "integration_id": "suricata-lab",
        "kind": "suricata",
        "display_name": "Suricata lab",
    })
    assert sensor.status_code == 201
    event = sample_event("sensor-event-1", "suricata-lab")
    event["source"] = {"integration_id": "suricata-lab", "kind": "suricata"}
    event["event_type"] = "network.connection"
    event["payload"] = {"src_ip": "198.51.100.23", "dest_ip": "192.0.2.15"}
    assert client.post("/api/v1/events", json=event).status_code == 202
    matches = client.get("/api/v1/threat-intel/matches").json()
    assert matches["count"] == 1
    assert matches["items"][0]["indicator"]["indicator_id"] == "misp-uuid-1"
    assert matches["items"][0]["event"]["event_id"] == "sensor-event-1"


def test_misp_sync_rejects_wrong_kind_and_disabled_integration():
    register_integration("router-lab")
    assert client.post("/api/v1/integrations/router-lab/misp-sync").status_code == 404
    created = client.post("/api/v1/integrations", json={
        "integration_id": "misp-disabled",
        "kind": "misp",
        "display_name": "Disabled MISP",
    })
    assert created.status_code == 201
    assert client.patch("/api/v1/integrations/misp-disabled", json={"enabled": False}).status_code == 200
    assert client.post("/api/v1/integrations/misp-disabled/misp-sync").status_code == 409


def test_threat_match_does_not_match_domain_suffix_or_invalid_ip():
    from openshield.api import main

    created = client.post("/api/v1/integrations", json={
        "integration_id": "suricata-lab",
        "kind": "suricata",
        "display_name": "Suricata lab",
    })
    assert created.status_code == 201
    main.store.upsert_threat_indicators("suricata-lab", [{
        "indicator_id": "domain-1",
        "indicator_type": "domain",
        "value": "evil.example",
        "to_ids": True,
    }])
    event = sample_event("domain-event", "suricata-lab")
    event["source"] = {"integration_id": "suricata-lab", "kind": "suricata"}
    event["payload"] = {"domain": "sub.evil.example"}
    assert client.post("/api/v1/events", json=event).status_code == 202
    assert client.get("/api/v1/threat-intel/matches").json()["count"] == 0
