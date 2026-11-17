from datetime import UTC, datetime
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from openshield.api.routers.gateway import create_gateway_router
from openshield.api.routers.health import create_health_router
from openshield.api.routers.integrations import create_integrations_router
from openshield.api.routers.metrics import create_metrics_router


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
    from openshield.integrations.registry import IntegrationRegistry

    class ProbeAdapter:
        def probe(self, integration):
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
