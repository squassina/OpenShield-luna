import json
from unittest.mock import MagicMock, patch

import pytest

from openshield.events.models import EventEnvelope, EventSource, Severity
from openshield.gateway.agent import run_agent
from openshield.gateway.client import GatewayConnectorClient, GatewayTransportError
from openshield.gateway.spool import GatewayEventSpool, SpoolFullError
from openshield.integrations.models import Capability


def make_client() -> GatewayConnectorClient:
    return GatewayConnectorClient(
        node_url="https://openshield.example",
        gateway_id="test-gateway",
        api_key="g" * 64,
    )


def test_connector_client_sends_authenticated_versioned_handshake() -> None:
    response = MagicMock()
    response.__enter__.return_value.read.return_value = json.dumps(
        {"status": "connected", "gateway_id": "test-gateway"}
    ).encode()
    with patch("openshield.gateway.client.urlopen", return_value=response) as urlopen_mock:
        result = make_client().connect()

    request = urlopen_mock.call_args.args[0]
    assert request.full_url == "https://openshield.example/api/v1/gateway/connect"
    assert request.get_header("Authorization") == f"Bearer {'g' * 64}"
    payload = json.loads(request.data)
    assert payload["protocol_version"] == "openshield.gateway.v1"
    assert payload["capabilities"] == []
    assert result["status"] == "connected"


def test_connector_client_rejects_invalid_configuration() -> None:
    with pytest.raises(ValueError, match="absolute HTTP"):
        GatewayConnectorClient("openshield.example", "test-gateway", "g" * 64)
    with pytest.raises(ValueError, match="32 characters"):
        GatewayConnectorClient("http://localhost:8000", "test-gateway", "short")
    with pytest.raises(ValueError, match="credentials"):
        GatewayConnectorClient("https://user:pass@example.com", "test-gateway", "g" * 64)


def test_connector_agent_rejects_unsafe_heartbeat_interval() -> None:
    with pytest.raises(ValueError, match="between 5 and 60"):
        run_agent(make_client(), heartbeat_interval=1)


def test_connector_client_surfaces_transport_failures() -> None:
    from urllib.error import URLError

    with (
        patch("openshield.gateway.client.urlopen", side_effect=URLError("offline")),
        pytest.raises(GatewayTransportError, match="Unable to reach"),
    ):
        make_client().heartbeat()


def test_connector_agent_reconnects_after_transport_loss(monkeypatch: pytest.MonkeyPatch) -> None:
    from openshield.gateway import agent

    class FakeClient:
        connect_calls = 0
        heartbeat_calls = 0

        def connect(self) -> dict[str, object]:
            self.connect_calls += 1
            if self.connect_calls == 1:
                raise GatewayTransportError("offline")
            return {"gateway_id": "test-gateway"}

        def heartbeat(self) -> dict[str, object]:
            self.heartbeat_calls += 1
            raise GatewayTransportError("connection lost")

    client = FakeClient()
    sleeps = iter([None, None, KeyboardInterrupt])

    def fake_sleep(_delay: float) -> None:
        result = next(sleeps)
        if result is KeyboardInterrupt:
            raise KeyboardInterrupt

    monkeypatch.setattr(agent.time, "sleep", fake_sleep)
    with pytest.raises(KeyboardInterrupt):
        run_agent(client, heartbeat_interval=5)

    assert client.connect_calls == 3
    assert client.heartbeat_calls == 1



def test_connector_client_advertises_only_configured_capabilities() -> None:
    response = MagicMock()
    response.__enter__.return_value.read.return_value = json.dumps(
        {"status": "connected", "gateway_id": "test-gateway"}
    ).encode()
    client = GatewayConnectorClient(
        node_url="https://openshield.example",
        gateway_id="test-gateway",
        api_key="g" * 64,
        capabilities=[Capability.DISCOVER, Capability.HEALTH_CHECK],
    )
    with patch("openshield.gateway.client.urlopen", return_value=response) as mocked:
        client.connect()

    payload = json.loads(mocked.call_args.args[0].data)
    assert payload["capabilities"] == ["discover", "health_check"]


def test_connector_client_posts_versioned_event_to_node() -> None:
    response = MagicMock()
    response.__enter__.return_value.read.return_value = json.dumps(
        {"status": "accepted", "event_id": "event-1"}
    ).encode()
    event = EventEnvelope(
        schema_version="openshield.event.v1",
        event_id="event-1",
        source=EventSource(integration_id="router-lab", kind="openwrt"),
        event_type="gateway.health",
        occurred_at="2026-01-01T12:00:00Z",
        observed_at="2026-01-01T12:00:01Z",
        severity=Severity.INFO,
        payload={"status": "reachable"},
    )
    with patch("openshield.gateway.client.urlopen", return_value=response) as mocked:
        result = make_client().ingest_event(event)

    request = mocked.call_args.args[0]
    assert request.full_url == "https://openshield.example/api/v1/events"
    assert request.get_header("Authorization") == f"Bearer {'g' * 64}"
    assert json.loads(request.data)["source"]["integration_id"] == "router-lab"
    assert result["status"] == "accepted"


def test_connector_agent_forwards_discovery_and_periodic_health(monkeypatch: pytest.MonkeyPatch) -> None:
    from openshield.gateway import agent

    class FakeNodeClient:
        def __init__(self) -> None:
            self.events: list[EventEnvelope] = []
            self.heartbeat_calls = 0

        def connect(self) -> dict[str, object]:
            return {"gateway_id": "test-gateway"}

        def heartbeat(self) -> dict[str, object]:
            self.heartbeat_calls += 1
            return {"status": "acknowledged"}

        def ingest_event(self, event: EventEnvelope) -> dict[str, object]:
            self.events.append(event)
            return {"status": "accepted"}

    class FakeOpenWrtClient:
        def discover(self) -> dict[str, object]:
            return {"board": {"hostname": "router"}, "interfaces": []}

        def health_check(self) -> dict[str, object]:
            return {"status": "reachable", "hostname": "router"}

    node = FakeNodeClient()
    sleeps = iter([None, KeyboardInterrupt])

    def fake_sleep(_delay: float) -> None:
        result = next(sleeps)
        if result is KeyboardInterrupt:
            raise KeyboardInterrupt

    monkeypatch.setattr(agent.time, "sleep", fake_sleep)
    with pytest.raises(KeyboardInterrupt):
        run_agent(
            node,
            heartbeat_interval=5,
            openwrt_client=FakeOpenWrtClient(),
            integration_id="router-lab",
        )

    assert node.heartbeat_calls == 1
    assert [event.event_type for event in node.events] == [
        "gateway.discovery",
        "gateway.health",
    ]
    assert all(event.schema_version == "openshield.event.v1" for event in node.events)
    assert all(event.source.integration_id == "router-lab" for event in node.events)



def sample_gateway_event(event_id: str = "spooled-event") -> EventEnvelope:
    return EventEnvelope(
        schema_version="openshield.event.v1",
        event_id=event_id,
        source=EventSource(integration_id="test-gateway", kind="openwrt"),
        event_type="gateway.health",
        occurred_at="2026-01-01T12:00:00Z",
        observed_at="2026-01-01T12:00:01Z",
        severity=Severity.INFO,
        payload={"status": "reachable"},
    )


def test_gateway_spool_survives_recreation_and_acknowledges(tmp_path) -> None:
    path = tmp_path / "gateway-spool.sqlite3"
    spool = GatewayEventSpool(str(path))
    event = sample_gateway_event()
    assert spool.enqueue(event) is True
    assert spool.pending_count() == 1

    restarted_spool = GatewayEventSpool(str(path))
    assert restarted_spool.pending() == [event]
    restarted_spool.acknowledge(event.event_id)
    assert restarted_spool.pending_count() == 0
    assert path.stat().st_mode & 0o777 == 0o600


def test_gateway_spool_enforces_capacity(tmp_path) -> None:
    spool = GatewayEventSpool(str(tmp_path / "limited.sqlite3"), max_events=1)
    spool.enqueue(sample_gateway_event("event-one"))
    with pytest.raises(SpoolFullError, match="spool is full"):
        spool.enqueue(sample_gateway_event("event-two"))
    assert spool.pending_count() == 1


def test_agent_retains_event_when_node_delivery_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    from openshield.gateway import agent

    class OfflineNodeClient:
        def connect(self) -> dict[str, object]:
            return {"gateway_id": "test-gateway"}

        def ingest_event(self, _event: EventEnvelope) -> dict[str, object]:
            raise GatewayTransportError("offline")

    class FakeOpenWrtClient:
        def discover(self) -> dict[str, object]:
            return {"board": {"hostname": "router"}, "interfaces": []}

    spool = GatewayEventSpool(str(tmp_path / "offline.sqlite3"))
    monkeypatch.setattr(agent.time, "sleep", lambda _delay: (_ for _ in ()).throw(KeyboardInterrupt))
    with pytest.raises(KeyboardInterrupt):
        run_agent(
            OfflineNodeClient(),
            heartbeat_interval=5,
            openwrt_client=FakeOpenWrtClient(),
            integration_id="test-gateway",
            spool=spool,
        )

    pending = spool.pending()
    assert len(pending) == 1
    assert pending[0].event_type == "gateway.discovery"
