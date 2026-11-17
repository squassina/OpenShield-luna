from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from openshield.api.routers.events import create_events_router
from openshield.api.routers.gateway import create_gateway_router
from openshield.api.routers.health import create_health_router
from openshield.api.routers.incidents import create_incidents_router
from openshield.api.routers.integration_credentials import create_integration_credentials_router
from openshield.api.routers.integration_tests import create_integration_test_router
from openshield.api.routers.integrations import create_integrations_router
from openshield.api.routers.inventory import create_inventory_router
from openshield.api.routers.metrics import create_metrics_router
from openshield.api.routers.policy_execution import create_policy_execution_router
from openshield.api.routers.threat_intel import create_threat_intel_router
from openshield.integrations.models import (
    Integration,
    IntegrationRegistration,
    IntegrationUpdate,
)
from openshield.integrations.registry import IntegrationRegistry


class FakeStore:
    def get_integration_secret(self, _integration_id: str):
        return None

    def list_pending_gateway_commands(self, _gateway_id: str, limit: int):
        assert limit == 10
        return []


class FakeRegistry:
    def __init__(self) -> None:
        self.registered = []

    def get(self, _integration_id: str):
        return None

    def register(self, registration):
        self.registered.append(registration)
        return SimpleNamespace(
            integration_id=registration.integration_id,
            kind=registration.kind,
        )


class FakeGatewayConnections:
    def connect(self, request):
        return SimpleNamespace(
            gateway_id=request.gateway_id,
            protocol_version=request.protocol_version,
            capabilities=request.capabilities,
            connected_at=datetime.now(UTC),
        )

    def heartbeat(self, _gateway_id: str):
        return None

    def list_status(self):
        return [{"gateway_id": "router-1", "status": "connected"}]

    def get_status(self, gateway_id: str):
        return {"gateway_id": gateway_id, "status": "connected"}


class FakeMetrics:
    def __init__(self) -> None:
        self.counters = []

    def increment(self, name: str) -> None:
        self.counters.append(name)

    def render(self) -> str:
        return "# HELP openshield_test_metric Test metric\n"


def test_health_router_is_independently_testable() -> None:
    class Store:
        ready = True

        def is_ready(self) -> bool:
            return self.ready

    store = Store()
    app = FastAPI()
    app.include_router(create_health_router(store))
    client = TestClient(app)

    assert client.get("/health/live").json() == {"status": "alive"}
    assert client.get("/health/ready").json() == {"status": "ready"}
    store.ready = False
    assert client.get("/health/ready").status_code == 503


def test_metrics_router_is_independently_testable() -> None:
    app = FastAPI()
    app.include_router(create_metrics_router(FakeMetrics()))
    response = TestClient(app).get("/metrics")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert response.text.startswith("# HELP openshield_test_metric")


def test_gateway_router_is_independently_testable() -> None:
    store = FakeStore()
    registry = FakeRegistry()
    connections = FakeGatewayConnections()
    metrics = FakeMetrics()
    app = FastAPI()
    app.include_router(create_gateway_router(
        store=store,
        registry=registry,
        gateway_connections=connections,
        metrics=metrics,
        gateway_openwrt_config=lambda _gateway_id: None,
        gateway_token_valid=lambda _request: True,
    ))
    client = TestClient(app)

    response = client.post("/api/v1/gateway/connect", json={
        "protocol_version": "openshield.gateway.v1",
        "gateway_id": "router-1",
        "gateway_type": "openwrt",
        "connector_version": "1.0.0",
        "capabilities": ["discover", "health_check"],
    })

    assert response.status_code == 201
    assert response.json()["integration_id"] == "router-1"
    assert registry.registered[0].integration_id == "router-1"
    assert metrics.counters == ["openshield_gateway_connections_total"]
    assert client.get("/api/v1/gateways").json() == [
        {"gateway_id": "router-1", "status": "connected"},
    ]


def test_integrations_router_is_independently_testable() -> None:
    class ProbeAdapter:
        def probe(self, integration: Integration) -> dict[str, object]:
            return {"integration_id": integration.integration_id, "status": "configured"}

    app = FastAPI()
    app.include_router(create_integrations_router(
        store=FakeStore(),
        registry=IntegrationRegistry(),
        adapters={"pihole": ProbeAdapter()},
    ))
    client = TestClient(app)

    created = client.post("/api/v1/integrations", json={
        "integration_id": "dns-home",
        "kind": "pihole",
        "display_name": "Home DNS",
    })
    assert created.status_code == 201
    assert created.json()["integration_id"] == "dns-home"

    listed = client.get("/api/v1/integrations")
    assert listed.status_code == 200
    assert listed.json()[0]["config"]["auth_configured"] is False

    probed = client.get("/api/v1/integrations/dns-home/probe")
    assert probed.status_code == 200
    assert probed.json() == {
        "integration_id": "dns-home",
        "status": "configured",
        "credentials_configured": False,
    }

    updated = client.patch("/api/v1/integrations/dns-home", json={
        "display_name": "Updated DNS",
    })
    assert updated.status_code == 200
    assert updated.json()["display_name"] == "Updated DNS"

    assert client.patch("/api/v1/integrations/dns-home", json={}).status_code == 422
    assert client.delete("/api/v1/integrations/dns-home").status_code == 204
    assert client.get("/api/v1/integrations/dns-home/probe").status_code == 404


def test_integration_connection_router_is_independently_testable() -> None:
    registry = IntegrationRegistry()
    registry.register(IntegrationRegistration(
        integration_id="sensor-lab",
        kind="suricata",
        display_name="Lab sensor",
    ))
    app = FastAPI()
    app.include_router(create_integration_test_router(
        store=FakeStore(),
        registry=registry,
        ssl_context_kwargs=lambda _integration, _url: {},
    ))
    client = TestClient(app)

    response = client.post("/api/v1/integrations/sensor-lab/test")
    assert response.status_code == 200
    assert response.json() == {
        "status": "configured",
        "integration_id": "sensor-lab",
        "mode": "push",
        "ingestion_endpoint": "/api/v1/sensors/sensor-lab/events",
    }

    registry.update("sensor-lab", IntegrationUpdate(enabled=False))
    assert client.post("/api/v1/integrations/sensor-lab/test").status_code == 409
    assert client.post("/api/v1/integrations/missing/test").status_code == 404


def test_integration_credentials_router_is_independently_testable() -> None:
    app = FastAPI()
    app.include_router(create_integration_credentials_router(
        store=FakeStore(),
        registry=IntegrationRegistry(),
        ssl_context_kwargs=lambda _integration, _url: {},
    ))
    client = TestClient(app)

    response = client.delete("/api/v1/integrations/missing/opnsense-credentials")
    assert response.status_code == 404


def test_incidents_router_is_independently_testable() -> None:
    class IncidentStore(FakeStore):
        def list_incidents(self, *, limit: int, status: str | None = None):
            assert limit == 100
            assert status is None
            return []

        def get_incident(self, _incident_id: str):
            return None

        def update_incident_status(
            self, _incident_id: str, _status: str, _reason: str = ""
        ):
            return None

    app = FastAPI()
    app.include_router(create_incidents_router(
        store=IncidentStore(),
        registry=IntegrationRegistry(),
        investigate=lambda *_args: {"status": "investigated"},
    ))
    client = TestClient(app)

    assert client.get("/api/v1/incidents").json() == []
    assert client.get("/api/v1/incidents/missing").status_code == 404
    assert client.get("/api/v1/incidents/missing/investigations").status_code == 404
    assert client.patch(
        "/api/v1/incidents/missing",
        json={"status": "closed", "reason": "test"},
    ).status_code == 404
    assert client.get("/api/v1/incidents?status=invalid").status_code == 422


def test_policy_execution_router_is_independently_testable() -> None:
    class PolicyStore(FakeStore):
        def __init__(self) -> None:
            self.emergency_stop = True

        def list_policies(self):
            return [{"policy_id": "policy-1"}]

        def get_emergency_stop(self):
            return self.emergency_stop

        def list_policy_decisions(self, limit):
            assert limit == 25
            return []

        def list_response_executions(self, limit):
            assert limit == 25
            return []

        def get_policy(self, policy_id):
            return {"policy_id": policy_id} if policy_id == "policy-1" else None

        def update_policy(self, policy_id, values):
            return {"policy_id": policy_id, **values}

        def set_emergency_stop(self, active):
            self.emergency_stop = active

    store = PolicyStore()
    registry = IntegrationRegistry()
    connections = FakeGatewayConnections()
    created = []
    app = FastAPI()
    app.include_router(create_policy_execution_router(
        store=store,
        registry=registry,
        gateway_connections=connections,
        create_policy_fn=lambda _store, _registry, data: created.append(data) or {
            "policy_id": "policy-1", **data,
        },
        evaluate_policy_fn=lambda *_args: {"status": "observe_only"},
        approve_decision_fn=lambda *_args: {"status": "active"},
        reject_decision_fn=lambda _store, _decision_id, reason: {
            "status": "rejected",
            "reason": reason,
        },
        enforcement_enabled_fn=lambda: True,
        max_autonomy_level_fn=lambda: 2,
    ))
    client = TestClient(app)

    listed = client.get("/api/v1/policies")
    assert listed.status_code == 200
    assert listed.json()["max_autonomy_level"] == 2
    assert listed.json()["items"] == [{"policy_id": "policy-1"}]

    payload = {
        "name": "Observe suspicious domain",
        "indicator_type": "domain",
        "indicator_value": "malicious.example",
        "action": "block_domain",
        "integration_id": "pihole-home",
        "min_risk_score": 70,
    }
    response = client.post("/api/v1/policies", json=payload)
    assert response.status_code == 201
    assert response.json()["policy_id"] == "policy-1"
    assert created[0]["name"] == payload["name"]

    missing = client.patch("/api/v1/policies/missing", json={"enabled": False})
    assert missing.status_code == 404
    assert client.patch("/api/v1/policies/policy-1", json={"enabled": False}).json() == {
        "policy_id": "policy-1", "enabled": False,
    }
    assert client.get("/api/v1/policy-decisions?limit=25").json() == []
    assert client.get("/api/v1/executions?limit=25").json() == []
    assert client.get("/api/v1/policy-decisions?limit=201").status_code == 422

    stopped = client.post("/api/v1/control/emergency-stop", json={"active": False})
    assert stopped.status_code == 200
    assert store.emergency_stop is False
    assert client.post("/api/v1/incidents/incident-1/evaluate", json={
        "policy_id": "policy-1",
    }).json() == {"status": "observe_only"}
    assert client.post("/api/v1/policy-decisions/decision-1/approve").json() == {
        "status": "active",
    }
    assert client.post("/api/v1/policy-decisions/decision-1/reject", json={
        "reason": "Not approved",
    }).json() == {"status": "rejected", "reason": "Not approved"}


def test_threat_intel_router_is_independently_testable() -> None:
    class ThreatIntelStore(FakeStore):
        def list_threat_indicators(self, *, integration_id=None, limit=200):
            assert integration_id == "misp-lab"
            assert limit == 25
            return [{"indicator_id": "ioc-1", "value": "198.51.100.1"}]

    app = FastAPI()
    app.include_router(create_threat_intel_router(
        store=ThreatIntelStore(),
        registry=FakeRegistry(),
        ssl_context_kwargs=lambda _integration, _url: {},
        enrich=lambda _store, _registry, event_ids: {"event_ids": event_ids},
    ))
    client = TestClient(app)

    response = client.get(
        "/api/v1/threat-intel/indicators?integration_id=misp-lab&limit=25"
    )
    assert response.status_code == 200
    assert response.json() == {
        "items": [{"indicator_id": "ioc-1", "value": "198.51.100.1"}],
        "count": 1,
    }
    enriched = client.post(
        "/api/v1/threat-intel/enrich",
        json={"event_ids": ["event-1", "event-1", "event-2"]},
    )
    assert enriched.status_code == 200
    assert enriched.json() == {"event_ids": ["event-1", "event-2"]}


def test_inventory_router_is_independently_testable() -> None:
    now = datetime.now(UTC)
    first_seen = now - timedelta(days=365)

    class InventoryStore(FakeStore):
        def list_gateway_discovery_snapshots(self):
            return [{
                "gateway_id": "router-1",
                "observed_at": now,
                "payload": {
                    "board": {"hostname": "home-router"},
                    "interfaces": [{
                        "name": "lan",
                        "device": "br-lan",
                        "vlan_id": 10,
                        "subnets": [{"subnet": "10.0.0.0/24"}],
                    }],
                },
            }]

        def list_gateway_devices(self, limit=None):
            return [{
                "gateway_id": "router-1",
                "mac_address": "aa:bb:cc:dd:ee:ff",
                "first_seen_at": first_seen,
                "last_seen_at": now,
                "payload": {
                    "name": "desktop",
                    "vendor": "Example",
                    "interface": "lan",
                },
            }]

        def list_device_identity_observations(self):
            return [{
                "ip_address": "10.0.0.5",
                "gateway_id": "router-1",
                "mac_address": "aa:bb:cc:dd:ee:ff",
                "source": "gateway.discovery",
                "confidence": "high",
                "first_seen_at": first_seen,
                "last_seen_at": now,
            }]

        def list_inventory_observations(self, *, limit):
            assert limit == 500
            return [{
                "ip_address": "10.0.0.5",
                "protocols": {"tcp", "udp"},
                "first_seen": first_seen,
                "last_seen": now,
                "observations": 3,
            }]

        def list_topology_observations(self, *, limit):
            assert limit == 1000
            return [{
                "source": "10.0.0.5",
                "target": "8.8.8.8",
                "protocol": "tcp",
                "observations": 2,
                "source_integration_ids": ["sensor-1"],
                "source_event_types": ["flow"],
                "first_seen": first_seen,
                "last_seen": now,
            }]

        def list_nat_observations(self, *, limit):
            assert limit == 1000
            return []

    app = FastAPI()
    app.include_router(create_inventory_router(store=InventoryStore()))
    client = TestClient(app)

    router_devices = client.get("/api/v1/inventory/router-devices")
    assert router_devices.status_code == 200
    assert router_devices.json()["gateways"][0]["board"]["hostname"] == "home-router"
    assert router_devices.json()["devices"][0]["status"] == "online"

    devices = client.get("/api/v1/inventory/devices")
    assert devices.status_code == 200
    assert devices.json()[0]["mac_address"] == "aa:bb:cc:dd:ee:ff"
    assert devices.json()[0]["network_segments"][0]["subnet"] == "10.0.0.0/24"

    topology = client.get("/api/v1/inventory/topology")
    assert topology.status_code == 200
    assert topology.json()["nodes"] == ["10.0.0.5", "8.8.8.8"]
    assert topology.json()["edges"][0]["direction"] == "outbound"
    assert topology.json()["relationships"][0]["relationship"] == "network_segment_membership"
    assert client.get("/api/v1/inventory/devices?limit=0").status_code == 422



def test_events_router_is_independently_testable() -> None:
    now = datetime.now(UTC)

    class EventsStore(FakeStore):
        def __init__(self) -> None:
            self.events = []
            self.audits = []
            self.discovery = []

        def write_audit(self, action, actor_id, target_id, details):
            self.audits.append({
                "action": action, "actor_id": actor_id,
                "target_id": target_id, "details": details,
            })

        def insert_event(self, event):
            if any(item.event_id == event.event_id for item in self.events):
                return False
            self.events.append(event)
            return True

        def record_gateway_discovery(self, integration_id, payload, observed_at):
            self.discovery.append((integration_id, payload, observed_at))

        def list_events_page(self, *, integration_id, event_type, severity, limit, cursor):
            items = [
                item for item in self.events
                if (integration_id is None or item.source.integration_id == integration_id)
                and (event_type is None or item.event_type == event_type)
                and (severity is None or item.severity.value == severity)
            ]
            return items[:limit], None

        def sensor_event_stats(self):
            return {"sensor-1": {"last_observed_at": now, "events_seen": len(self.events)}}

    class EventsRegistry(FakeRegistry):
        def __init__(self) -> None:
            super().__init__()
            self.integrations = {
                "router-1": SimpleNamespace(
                    integration_id="router-1", kind="openwrt", enabled=True,
                ),
                "sensor-1": SimpleNamespace(
                    integration_id="sensor-1", kind="suricata", enabled=True,
                    display_name="Lab sensor",
                ),
            }

        def get(self, integration_id):
            return self.integrations.get(integration_id)

        def list_all(self):
            return list(self.integrations.values())

    store = EventsStore()
    registry = EventsRegistry()
    metrics = FakeMetrics()
    app = FastAPI()
    app.include_router(create_events_router(
        store=store,
        registry=registry,
        metrics=metrics,
        gateway_token_valid=lambda request: request.headers.get("Authorization") == "Bearer gateway",
    ))
    client = TestClient(app)

    event = {
        "schema_version": "openshield.event.v1",
        "event_id": "event-1",
        "source": {"integration_id": "router-1", "kind": "openwrt"},
        "event_type": "gateway.discovery",
        "occurred_at": now.isoformat(),
        "observed_at": now.isoformat(),
        "severity": "info",
        "payload": {"board": {"hostname": "router"}},
    }
    assert client.post("/api/v1/events", json=event).status_code == 401
    accepted = client.post(
        "/api/v1/events", json=event, headers={"Authorization": "Bearer gateway"},
    )
    assert accepted.status_code == 202
    assert accepted.json() == {"status": "accepted", "event_id": "event-1"}
    assert store.discovery[0][0] == "router-1"
    assert client.post(
        "/api/v1/events", json=event, headers={"Authorization": "Bearer gateway"},
    ).json()["status"] == "duplicate"
    assert client.get("/api/v1/events?integration_id=router-1").json()["items"][0]["event_id"] == "event-1"
    assert client.get("/api/v1/events?cursor=invalid").status_code == 422

    sensor = client.post("/api/v1/sensors/sensor-1/events", json=[{
        "event_type": "flow", "timestamp": now.isoformat(),
        "src_ip": "192.0.2.10", "dest_ip": "198.51.100.20",
    }])
    assert sensor.status_code == 202
    assert sensor.json() == {"accepted": 1, "duplicates": 0, "received": 1}
    health = client.get("/api/v1/sensors")
    assert health.status_code == 200
    assert health.json()[0]["status"] == "healthy"
    assert health.json()[0]["events_seen"] == 2
    assert metrics.counters == [
        "openshield_events_ingested_total",
        "openshield_events_ingested_total",
    ]
