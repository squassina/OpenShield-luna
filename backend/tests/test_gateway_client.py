import json
from unittest.mock import MagicMock, patch

import pytest

from openshield.gateway.agent import run_agent
from openshield.gateway.client import GatewayConnectorClient, GatewayTransportError


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
