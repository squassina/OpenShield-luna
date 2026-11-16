import json
from pathlib import Path
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
    )


def test_connector_client_sends_versioned_handshake_without_credentials() -> None:
    response = MagicMock()
    response.__enter__.return_value.read.return_value = json.dumps(
        {"status": "connected", "gateway_id": "test-gateway"}
    ).encode()
    with patch("openshield.gateway.client.urlopen", return_value=response) as urlopen_mock:
        result = make_client().connect()

    request = urlopen_mock.call_args.args[0]
    assert request.full_url == "https://openshield.example/api/v1/gateway/connect"
    assert request.get_header("Authorization") is None
    payload = json.loads(request.data)
    assert payload["protocol_version"] == "openshield.gateway.v1"
    assert payload["capabilities"] == []
    assert result["status"] == "connected"


def test_connector_client_rejects_invalid_configuration() -> None:
    with pytest.raises(ValueError, match="absolute HTTP"):
        GatewayConnectorClient("openshield.example", "test-gateway")
    with pytest.raises(ValueError, match="credentials"):
        GatewayConnectorClient("https://user:pass@example.com", "test-gateway")


def test_connector_agent_rejects_unsafe_heartbeat_interval() -> None:
    with pytest.raises(ValueError, match="between 5 and 60"):
        run_agent(make_client(), heartbeat_interval=1)


def test_connector_client_heartbeat_includes_gateway_identity() -> None:
    response = MagicMock()
    response.__enter__.return_value.read.return_value = json.dumps(
        {"status": "acknowledged", "gateway_id": "test-gateway"}
    ).encode()
    with patch("openshield.gateway.client.urlopen", return_value=response) as mocked:
        make_client().heartbeat()

    request = mocked.call_args.args[0]
    assert request.get_header("Authorization") is None
    assert json.loads(request.data) == {
        "protocol_version": "openshield.gateway.v1",
        "gateway_id": "test-gateway",
    }


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
    assert request.get_header("Authorization") is None
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


def test_gateway_spool_survives_recreation_and_acknowledges(tmp_path: Path) -> None:
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
    assert path.parent.stat().st_mode & 0o777 == 0o700


def test_gateway_spool_requires_absolute_path() -> None:
    with pytest.raises(ValueError, match="absolute"):
        GatewayEventSpool("relative-spool.sqlite3")


def test_gateway_spool_enforces_capacity_without_evicting_security_events(
    tmp_path: Path,
) -> None:
    spool = GatewayEventSpool(str(tmp_path / "limited.sqlite3"), max_events=1)
    first = sample_gateway_event("event-one").model_copy(
        update={"event_type": "security.audit", "severity": Severity.CRITICAL}
    )
    second = sample_gateway_event("event-two").model_copy(
        update={"event_type": "security.audit", "severity": Severity.CRITICAL}
    )
    spool.enqueue(first)
    with pytest.raises(SpoolFullError, match="protected events were retained"):
        spool.enqueue(second)
    assert spool.pending() == [first]
    assert spool.stats() == {
        "evicted_events": 0,
        "coalesced_health_events": 0,
        "dropped_events": 1,
        "pending_events": 1,
        "capacity": 1,
    }


def test_gateway_spool_evicts_oldest_low_priority_event_for_health(
    tmp_path: Path,
) -> None:
    spool = GatewayEventSpool(str(tmp_path / "priority.sqlite3"), max_events=1)
    telemetry = sample_gateway_event("telemetry").model_copy(
        update={"event_type": "gateway.discovery"}
    )
    health = sample_gateway_event("health")
    spool.enqueue(telemetry)

    assert spool.enqueue(health) is True
    assert spool.pending() == [health]
    assert spool.stats()["evicted_events"] == 1
    assert spool.stats()["pending_events"] == 1


def test_gateway_spool_compacts_duplicate_health_snapshots(
    tmp_path: Path,
) -> None:
    spool = GatewayEventSpool(str(tmp_path / "health.sqlite3"), max_events=1)
    first = sample_gateway_event("health-old")
    latest = sample_gateway_event("health-latest")
    spool.enqueue(first)

    assert spool.enqueue(latest) is True
    assert spool.pending() == [latest]
    assert spool.stats()["coalesced_health_events"] == 1


def test_gateway_spool_never_evicts_security_events_for_health(
    tmp_path: Path,
) -> None:
    spool = GatewayEventSpool(str(tmp_path / "protected.sqlite3"), max_events=1)
    security = sample_gateway_event("security-event").model_copy(
        update={"event_type": "security.alert", "severity": Severity.HIGH}
    )
    changed_health = sample_gateway_event("health-event").model_copy(
        update={"payload": {"status": "unavailable"}}
    )
    spool.enqueue(security)

    with pytest.raises(SpoolFullError, match="protected events were retained"):
        spool.enqueue(changed_health)
    assert spool.pending() == [security]
    assert spool.stats()["dropped_events"] == 1


def test_agent_retains_event_when_node_delivery_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
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
    def stop_agent(_delay: float) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(agent.time, "sleep", stop_agent)
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



def test_agent_collects_and_spools_health_while_node_is_offline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from openshield.gateway import agent

    class OfflineNodeClient:
        def connect(self) -> dict[str, object]:
            raise GatewayTransportError("node unavailable")

    class FakeOpenWrtClient:
        def discover(self) -> dict[str, object]:
            return {"board": {"hostname": "router"}, "interfaces": []}

        def health_check(self) -> dict[str, object]:
            return {"status": "reachable", "hostname": "router"}

    spool = GatewayEventSpool(str(tmp_path / "offline-connect.sqlite3"))

    def stop_agent(_delay: float) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(agent.time, "sleep", stop_agent)
    with pytest.raises(KeyboardInterrupt):
        run_agent(
            OfflineNodeClient(),
            heartbeat_interval=5,
            openwrt_client=FakeOpenWrtClient(),
            integration_id="test-gateway",
            spool=spool,
        )

    assert [event.event_type for event in spool.pending()] == [
        "gateway.discovery",
        "gateway.health",
    ]

def test_agent_retries_spooled_events_until_node_acknowledges(tmp_path: Path) -> None:
    from openshield.gateway import agent

    class RecoveringNodeClient:
        calls = 0

        def ingest_event(self, _event: EventEnvelope) -> dict[str, object]:
            self.calls += 1
            if self.calls == 1:
                raise GatewayTransportError("node unavailable")
            return {"status": "duplicate"}

    spool = GatewayEventSpool(str(tmp_path / "recovery.sqlite3"))
    event = sample_gateway_event("recovery-event")
    spool.enqueue(event)
    client = RecoveringNodeClient()

    assert agent._flush_spool(client, spool) is False
    assert spool.pending() == [event]

    assert agent._flush_spool(client, spool) is True
    assert spool.pending_count() == 0
    assert client.calls == 2


def test_gateway_outbox_persists_across_connector_recreation(tmp_path: Path) -> None:
    path = tmp_path / "independent.sqlite3"
    event = sample_gateway_event("offline-proof")
    GatewayEventSpool(str(path)).enqueue(event)
    restarted = GatewayEventSpool(str(path))
    assert restarted.pending() == [event]


def test_connector_client_sends_gateway_bearer_token_and_receives_router_config() -> None:
    response = MagicMock()
    response.__enter__.return_value.read.return_value = json.dumps({
        "status": "connected", "gateway_id": "home-gateway",
        "openwrt_config": {
            "base_url": "https://192.0.2.1", "username": "rpc", "password": "secret",
        },
    }).encode()
    client = GatewayConnectorClient(
        "https://openshield.example", "home-gateway", gateway_token="connector-token",
    )
    with patch("openshield.gateway.client.urlopen", return_value=response) as mocked:
        result = client.connect()
    request = mocked.call_args.args[0]
    assert request.get_header("Authorization") == "Bearer connector-token"
    assert result["openwrt_config"]["password"] == "secret"


def test_gateway_command_result_outbox_survives_restart_and_acknowledges(
    tmp_path: Path,
) -> None:
    path = tmp_path / "command-results.sqlite3"
    spool = GatewayEventSpool(str(path))
    result = {"status": "applied", "section": "rule-1"}

    assert spool.enqueue_command_result("command-1", "completed", result) is True
    assert spool.enqueue_command_result("command-1", "completed", result) is False

    restarted = GatewayEventSpool(str(path))
    assert restarted.pending_command_results() == [{
        "command_id": "command-1",
        "status": "completed",
        "result": result,
    }]
    restarted.acknowledge_command_result("command-1")
    assert restarted.pending_command_results() == []
    assert restarted.get_command_result("command-1") == {
        "command_id": "command-1",
        "status": "completed",
        "result": result,
        "acknowledged": True,
    }


def test_gateway_command_result_outbox_rejects_conflicting_duplicate(
    tmp_path: Path,
) -> None:
    spool = GatewayEventSpool(str(tmp_path / "conflict.sqlite3"))
    spool.enqueue_command_result("command-1", "completed", {"status": "applied"})

    with pytest.raises(ValueError, match="cannot be changed"):
        spool.enqueue_command_result("command-1", "failed", {"status": "failed"})


def test_gateway_command_result_delivery_survives_node_outage_without_reexecution(
    tmp_path: Path,
) -> None:
    import sqlite3
    from datetime import UTC, datetime, timedelta

    from openshield.gateway import agent

    class NodeClient:
        def __init__(self) -> None:
            self.unavailable = True
            self.reports: list[tuple[str, str, dict[str, object]]] = []

        def report_command_result(
            self,
            command_id: str,
            status: str,
            result: dict[str, object],
        ) -> dict[str, object]:
            if self.unavailable:
                raise GatewayTransportError("node unavailable")
            self.reports.append((command_id, status, result))
            return {"status": "acknowledged"}

    class RouterClient:
        calls = 0

        def apply_firewall_block(
            self,
            execution_id: str,
            ip_value: str,
            direction: str,
        ) -> dict[str, object]:
            self.calls += 1
            return {"section": "rule-1", "execution_id": execution_id}

    path = tmp_path / "command-outage.sqlite3"
    spool = GatewayEventSpool(str(path))
    node = NodeClient()
    router = RouterClient()
    command = {
        "command_id": "command-1",
        "execution_id": "execution-1",
        "action": "block_ip",
        "payload": {"ip": "192.0.2.10", "direction": "source"},
    }

    agent._process_gateway_commands(node, router, [command], spool)
    assert router.calls == 1
    persisted = spool.get_command_result("command-1")
    assert persisted["status"] == "completed"
    assert persisted["acknowledged"] is False
    assert spool.pending_command_results() == []  # Deferred by the durable retry backoff.

    # Simulate process restart and make the persisted retry immediately due.
    restarted = GatewayEventSpool(str(path))
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE gateway_command_results SET next_attempt_at = ?",
            ((datetime.now(UTC) - timedelta(seconds=1)).isoformat(),),
        )
        connection.commit()

    node.unavailable = False
    agent._process_gateway_commands(node, router, [command], restarted)
    assert router.calls == 1
    assert node.reports == [(
        "command-1", "completed",
        {"section": "rule-1", "execution_id": "execution-1", "status": "applied"},
    )]
    assert restarted.pending_command_results() == []
    assert restarted.get_command_result("command-1")["acknowledged"] is True
    agent._process_gateway_commands(node, router, [command], restarted)
    assert router.calls == 1
    assert len(node.reports) == 1


def test_gateway_failed_command_result_is_persisted_and_delivered(tmp_path: Path) -> None:
    from openshield.gateway import agent
    from openshield.integrations.openwrt_rpc import OpenWrtRPCError

    class NodeClient:
        def __init__(self) -> None:
            self.reports: list[tuple[str, str, dict[str, object]]] = []

        def report_command_result(
            self,
            command_id: str,
            status: str,
            result: dict[str, object],
        ) -> dict[str, object]:
            self.reports.append((command_id, status, result))
            return {"status": "acknowledged"}

    class RouterClient:
        def apply_firewall_block(self, *_args) -> dict[str, object]:
            raise OpenWrtRPCError("router rejected action")

    spool = GatewayEventSpool(str(tmp_path / "failed-command.sqlite3"))
    node = NodeClient()
    agent._process_gateway_commands(
        node,
        RouterClient(),
        [{
            "command_id": "command-failed",
            "execution_id": "execution-failed",
            "action": "block_ip",
            "payload": {"ip": "192.0.2.10", "direction": "source"},
        }],
        spool,
    )

    assert node.reports == [(
        "command-failed", "failed",
        {"status": "failed", "error": "gateway_command_failed"},
    )]
    assert spool.pending_command_results() == []
    assert spool.get_command_result("command-failed")["acknowledged"] is True


def test_gateway_command_result_retry_backoff_is_bounded(tmp_path: Path) -> None:
    import sqlite3
    from datetime import UTC, datetime

    path = tmp_path / "backoff.sqlite3"
    spool = GatewayEventSpool(str(path))
    spool.enqueue_command_result("command-backoff", "failed", {"status": "failed"})

    for _ in range(10):
        spool.defer_command_result("command-backoff")

    with sqlite3.connect(path) as connection:
        attempts, next_attempt_at = connection.execute(
            """
            SELECT attempts, next_attempt_at
            FROM gateway_command_results WHERE command_id = ?
            """,
            ("command-backoff",),
        ).fetchone()

    remaining = (
        datetime.fromisoformat(next_attempt_at) - datetime.now(UTC)
    ).total_seconds()
    assert attempts == 10
    assert 0 < remaining <= 60
    assert spool.pending_command_results() == []


def test_gateway_command_result_backoff_does_not_reorder_outbox(tmp_path: Path) -> None:
    import sqlite3
    from datetime import UTC, datetime, timedelta

    path = tmp_path / "ordered-results.sqlite3"
    spool = GatewayEventSpool(str(path))
    spool.enqueue_command_result("command-first", "completed", {"sequence": 1})
    spool.enqueue_command_result("command-second", "completed", {"sequence": 2})
    spool.defer_command_result("command-first")

    assert spool.pending_command_results() == []

    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE gateway_command_results SET next_attempt_at = ? WHERE command_id = ?",
            ((datetime.now(UTC) - timedelta(seconds=1)).isoformat(), "command-first"),
        )
        connection.commit()

    assert [item["command_id"] for item in spool.pending_command_results()] == [
        "command-first",
        "command-second",
    ]

def test_gateway_spool_health_compaction_keeps_state_transitions(
    tmp_path: Path,
) -> None:
    spool = GatewayEventSpool(str(tmp_path / "health-transition.sqlite3"), max_events=2)
    reachable = sample_gateway_event("health-reachable")
    unavailable = sample_gateway_event("health-unavailable").model_copy(
        update={"payload": {"status": "unavailable"}}
    )
    newest_reachable = sample_gateway_event("health-reachable-new")

    spool.enqueue(reachable)
    spool.enqueue(unavailable)
    # A matching snapshot may replace its older copy without losing the transition.
    spool.enqueue(newest_reachable)

    assert {event.payload["status"] for event in spool.pending()} == {
        "reachable",
        "unavailable",
    }
    assert any(event.event_id == "health-reachable-new" for event in spool.pending())
    assert spool.stats()["coalesced_health_events"] == 1

def test_configured_openwrt_client_receives_firewall_zone_mapping(monkeypatch) -> None:
    from openshield.gateway import agent

    zones = {
        "source": {"src": "iot", "dest": "dmz"},
        "destination": {"src": "guest", "dest": "lan"},
    }
    received: dict[str, object] = {}

    class FakeOpenWrtRPCClient:
        def __init__(
            self,
            base_url: str,
            username: str,
            password: str,
            **options: object,
        ) -> None:
            received.update(
                base_url=base_url,
                username=username,
                password=password,
                options=options,
            )

    monkeypatch.setattr(agent, "OpenWrtRPCClient", FakeOpenWrtRPCClient)
    result = agent._configured_openwrt_client({
        "base_url": "http://router",
        "username": "rpc",
        "password": "secret",
        "firewall_zones": zones,
    })

    assert isinstance(result, FakeOpenWrtRPCClient)
    assert received["options"] == {"firewall_zones": zones}

