import json
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from openshield.api.main import app
from openshield.core.secrets import SecretStore
from openshield.events.models import EventEnvelope, EventSource, Severity
from openshield.gateway.agent import _process_gateway_commands
from openshield.integrations.models import IntegrationRegistration
from openshield.integrations.openwrt_rpc import OpenWrtRPCClient
from openshield.policy.engine import create_policy, evaluate_policy
from openshield.execution import service as execution_service

client = TestClient(app)


def setup_function() -> None:
    from openshield.api import main

    main.store.reset()


def _register(kind: str, integration_id: str, config: dict | None = None) -> None:
    from openshield.api import main

    main.registry.register(IntegrationRegistration(
        integration_id=integration_id,
        kind=kind,
        display_name=integration_id,
        config=config or {},
    ))


def _incident(indicator_type: str = "domain", indicator_value: str = "malicious.example"):
    from openshield.api import main

    now = datetime.now(UTC)
    event = EventEnvelope(
        schema_version="openshield.event.v1",
        event_id="policy-event-1",
        source=EventSource(integration_id="sensor", kind="suricata"),
        event_type="network.suricata.alert",
        occurred_at=now,
        observed_at=now,
        severity=Severity.HIGH,
        payload={"indicator": indicator_value},
    )
    _register("suricata", "sensor")
    main.store.insert_event(event)
    return main.store.upsert_incident(
        {
            "incident_id": "policy-incident-1",
            "indicator_type": indicator_type,
            "indicator_value": indicator_value,
            "title": "Threat match",
            "summary": "Threat intelligence matched an observed indicator.",
            "risk_score": 85,
            "risk_level": "critical",
            "status": "open",
            "sources": ["crowdsec-home"],
            "risk_factors": [{"factor": "crowdsec_reputation", "points": 35}],
            "source_events": [{
                "event_id": event.event_id, "event_type": event.event_type,
                "source": "sensor", "severity": "high",
                "occurred_at": now.isoformat(),
            }],
            "intel_evidence": {},
            "created_at": now.isoformat(),
        },
        [event.event_id], now, now,
    )


def _policy(
    action: str = "block_domain", indicator_type: str = "domain",
    indicator_value: str = "malicious.example", integration_id: str = "pihole-home",
    autonomy_level: int = 1, require_approval: bool = True,
):
    from openshield.api import main

    return create_policy(main.store, main.registry, {
        "name": "Test policy",
        "enabled": True,
        "indicator_type": indicator_type,
        "indicator_value": indicator_value,
        "action": action,
        "integration_id": integration_id,
        "min_risk_score": 70,
        "autonomy_level": autonomy_level,
        "ttl_seconds": 600,
        "require_approval": require_approval,
        "direction": "destination",
    })


def _enable_enforcement(monkeypatch, autonomy: int = 1) -> None:
    monkeypatch.setenv("OPENSHIELD_ENFORCEMENT_ENABLED", "true")
    monkeypatch.setenv("OPENSHIELD_API_AUTH_ENABLED", "true")
    monkeypatch.setenv("OPENSHIELD_MAX_AUTONOMY_LEVEL", str(autonomy))
    from openshield.api import main

    main.store.set_emergency_stop(False)


def _rpc_response(payload: object) -> MagicMock:
    response = MagicMock()
    response.__enter__.return_value.read.return_value = json.dumps(payload).encode()
    return response


def test_policy_defaults_to_observe_only_and_emergency_stop_active() -> None:
    from openshield.api import main

    _register("pihole", "pihole-home")
    incident = _incident()
    policy = _policy(autonomy_level=0)
    assert main.store.get_emergency_stop() is True
    decision = evaluate_policy(
        main.store, main.registry, incident["incident_id"], policy["policy_id"],
        main.gateway_connections,
    )
    assert decision["status"] == "observe_only"
    assert main.store.list_response_executions() == []


def test_manual_approval_executes_dns_block_with_ttl_and_rolls_back(monkeypatch) -> None:
    from openshield.api import main

    _register("pihole", "pihole-home")
    incident = _incident()
    policy = _policy()
    _enable_enforcement(monkeypatch, 1)
    sync_calls = []
    monkeypatch.setattr(execution_service, "sync_provider_lists", lambda integration, items: (
        sync_calls.append([dict(item) for item in items]) or {"status": "synced"}
    ))
    decision = evaluate_policy(
        main.store, main.registry, incident["incident_id"], policy["policy_id"],
        main.gateway_connections,
    )
    assert decision["status"] == "pending_approval"
    execution = execution_service.approve_decision(
        main.store, main.registry, main.gateway_connections, decision["decision_id"],
    )
    assert execution["status"] == "active"
    assert execution["adapter_result"]["created_by_execution"] is True
    assert len(sync_calls) == 1
    assert any(
        item["domain"] == "malicious.example" and item["list_type"] == "block"
        for item in main.store.list_privacy_lists("pihole-home")
    )

    main.store.update_response_execution(
        execution["execution_id"], "active",
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    assert execution_service.expire_due_executions(main.store, main.registry) == 1
    rolled_back = main.store.get_response_execution(execution["execution_id"])
    assert rolled_back["status"] == "rolled_back"
    assert main.store.list_privacy_lists("pihole-home") == []
    assert len(sync_calls) == 2


def test_existing_manual_dns_block_is_never_removed_by_ttl(monkeypatch) -> None:
    from openshield.api import main

    _register("pihole", "pihole-home")
    incident = _incident()
    main.store.upsert_privacy_list("pihole-home", "block", "malicious.example", "Manual admin entry")
    _enable_enforcement(monkeypatch, 1)
    monkeypatch.setattr(execution_service, "sync_provider_lists", lambda *args: {"status": "synced"})
    policy = _policy()
    decision = evaluate_policy(
        main.store, main.registry, incident["incident_id"], policy["policy_id"],
        main.gateway_connections,
    )
    execution = execution_service.approve_decision(
        main.store, main.registry, main.gateway_connections, decision["decision_id"],
    )
    assert execution["adapter_result"]["created_by_execution"] is False
    main.store.update_response_execution(
        execution["execution_id"], "active",
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    execution_service.expire_due_executions(main.store, main.registry)
    assert main.store.get_response_execution(execution["execution_id"])["status"] == "rolled_back"
    assert main.store.list_privacy_lists("pihole-home")[0]["comment"] == "Manual admin entry"


def test_l2_automatic_execution_requires_explicit_policy_and_global_enable(monkeypatch) -> None:
    from openshield.api import main

    _register("pihole", "pihole-home")
    incident = _incident()
    _enable_enforcement(monkeypatch, 2)
    monkeypatch.setattr(execution_service, "sync_provider_lists", lambda *args: {"status": "synced"})
    policy = _policy(autonomy_level=2, require_approval=False)
    decision = evaluate_policy(
        main.store, main.registry, incident["incident_id"], policy["policy_id"],
        main.gateway_connections,
    )
    assert decision["status"] == "executed"
    assert decision["execution"]["status"] == "active"


def test_policy_rejects_indicator_mismatch_private_ip_and_wrong_adapter() -> None:
    from openshield.api import main

    _register("pihole", "pihole-home")
    _register("openwrt", "home-gateway")
    _incident()
    with pytest.raises(ValueError, match="public IP"):
        _policy("block_ip", "ip", "192.168.1.1", "home-gateway")
    with pytest.raises(ValueError, match="requires an OpenWrt"):
        _policy("block_ip", "ip", "8.8.8.8", "pihole-home")


def test_global_autonomy_cap_blocks_higher_policy(monkeypatch) -> None:
    from openshield.api import main

    _register("pihole", "pihole-home")
    incident = _incident()
    _enable_enforcement(monkeypatch, 1)
    policy = _policy(autonomy_level=2, require_approval=False)
    decision = evaluate_policy(
        main.store, main.registry, incident["incident_id"], policy["policy_id"],
        main.gateway_connections,
    )
    assert decision["status"] == "blocked"
    assert "autonomy_level_exceeds_global_cap" in decision["rationale"]["reasons"]


def test_openwrt_firewall_execution_uses_gateway_queue_and_ttl_rollback(monkeypatch) -> None:
    from openshield.api import main

    monkeypatch.setenv("OPENSHIELD_SECRET_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("OPENSHIELD_GATEWAY_TOKEN", "gateway-test-token")
    _register("openwrt", "home-gateway")
    SecretStore(main.store).set("home-gateway", {
        "base_url": "https://192.0.2.1", "username": "openshield", "password": "router-password",
    })
    incident = _incident("ip", "8.8.8.8")
    _enable_enforcement(monkeypatch, 1)
    policy = _policy("block_ip", "ip", "8.8.8.8", "home-gateway")
    decision = evaluate_policy(
        main.store, main.registry, incident["incident_id"], policy["policy_id"],
        main.gateway_connections,
    )
    assert decision["status"] == "pending_approval"
    execution = execution_service.approve_decision(
        main.store, main.registry, main.gateway_connections, decision["decision_id"],
    )
    assert execution["status"] == "pending_gateway"
    command = main.store.list_pending_gateway_commands("home-gateway")[0]
    active = execution_service.process_gateway_command_result(
        main.store, command["command_id"], "completed",
        {"status": "applied", "section": "os_abcdef1234567890", "verified": True},
    )
    assert active["status"] == "active"
    main.store.update_response_execution(
        execution["execution_id"], "active",
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    assert execution_service.expire_due_executions(main.store, main.registry) == 1
    assert main.store.get_response_execution(execution["execution_id"])["status"] == "rollback_pending"
    rollback = main.store.list_pending_gateway_commands("home-gateway")[0]
    assert rollback["action"] == "unblock_ip"
    result = execution_service.process_gateway_command_result(
        main.store, rollback["command_id"], "completed",
        {"status": "rolled_back", "section": "os_abcdef1234567890", "verified": True},
    )
    assert result["status"] == "rolled_back"


def test_failed_gateway_rollback_is_requeued_until_acknowledged() -> None:
    from openshield.api import main

    monkeypatch_env = {
        "OPENSHIELD_SECRET_KEY": Fernet.generate_key().decode(),
        "OPENSHIELD_GATEWAY_TOKEN": "gateway-test-token",
    }
    import os
    for key, value in monkeypatch_env.items():
        os.environ[key] = value
    _register("openwrt", "home-gateway")
    SecretStore(main.store).set("home-gateway", {
        "base_url": "https://192.0.2.1", "username": "openshield", "password": "router-password",
    })
    incident = _incident("ip", "8.8.8.8")
    main.store.create_policy({"policy_id":"policy-1","name":"test","enabled":True,
        "indicator_type":"ip","indicator_value":"8.8.8.8","action":"block_ip",
        "integration_id":"home-gateway","min_risk_score":70,"autonomy_level":1,
        "ttl_seconds":600,"require_approval":True,"direction":"destination"})
    decision=main.store.create_policy_decision("decision-1",incident["incident_id"],"policy-1","approved",{})
    execution=main.store.create_response_execution({
        "execution_id":"execution-1","decision_id":decision["decision_id"],
        "incident_id":incident["incident_id"],"policy_id":"policy-1","integration_id":"home-gateway",
        "action":"block_ip","indicator_type":"ip","indicator_value":"8.8.8.8",
        "direction":"destination","status":"rollback_failed","ttl_seconds":600,
        "expires_at":datetime.now(UTC)-timedelta(seconds=1),
        "adapter_result":{"section":"os_abcdef1234567890"},
    })
    assert execution_service.expire_due_executions(main.store, main.registry) == 1
    assert main.store.get_response_execution("execution-1")["status"] == "rollback_pending"
    assert main.store.list_pending_gateway_commands("home-gateway")[0]["action"] == "unblock_ip"


def test_gateway_command_agent_only_executes_allowlisted_actions() -> None:
    class FakeRPC:
        def apply_firewall_block(self, execution_id, ip_value, direction):
            return {"section": "os_abc", "verified": True}

        def remove_firewall_block(self, section):
            return {"section": section, "removed": True}

    class FakeClient:
        def __init__(self):
            self.results = []

        def report_command_result(self, command_id, status, result):
            self.results.append((command_id, status, result))
            return {}

    client_stub = FakeClient()
    _process_gateway_commands(client_stub, FakeRPC(), [
        {"command_id":"c1","execution_id":"e1","action":"block_ip",
         "payload":{"ip":"8.8.8.8","direction":"destination"}},
        {"command_id":"c2","execution_id":"e2","action":"run_shell",
         "payload":{"command":"rm -rf /"}},
    ])
    assert client_stub.results[0][1] == "completed"
    assert client_stub.results[0][2]["status"] == "applied"
    assert client_stub.results[1][1] == "failed"
    assert client_stub.results[1][2]["error"] == "gateway_command_failed"


def test_openwrt_rpc_adds_and_verifies_scoped_firewall_rule(monkeypatch) -> None:
    responses = [
        [0, {"ubus_rpc_session": "session-id"}],
        [0, {"section": "os_abcdef1234567890"}],
        [0, {}],
        [0, {"values": {"name": "OpenShield", "target": "REJECT"}}],
        [0, {}],
    ]
    requests = []

    def fake_urlopen(request, timeout):
        requests.append(request)
        return _rpc_response(responses.pop(0))

    monkeypatch.setattr("openshield.integrations.openwrt_rpc.urlopen", fake_urlopen)
    client_rpc = OpenWrtRPCClient("http://192.0.2.1", "openshield", "router-password")
    result = client_rpc.apply_firewall_block(
        "abcdef12-3456-7890-abcd-ef1234567890", "8.8.8.8", "destination",
    )
    assert result["verified"] is True
    add = json.loads(requests[1].data)[3]
    assert add["config"] == "firewall"
    assert add["type"] == "rule"
    assert add["values"]["src"] == "lan"
    assert add["values"]["dest"] == "wan"
    assert add["values"]["dest_ip"] == "8.8.8.8"
    assert add["values"]["target"] == "REJECT"
    assert json.loads(requests[2].data)[2] == "apply"
    assert json.loads(requests[4].data)[2] == "confirm"


def test_openwrt_rpc_removes_and_verifies_firewall_rule(monkeypatch) -> None:
    responses = [
        [0, {"ubus_rpc_session": "session-id"}],
        [0, {}],
        [0, {}],
        [0, {"values": {}}],
        [0, {}],
    ]
    requests = []

    def fake_urlopen(request, timeout):
        requests.append(request)
        return _rpc_response(responses.pop(0))

    monkeypatch.setattr("openshield.integrations.openwrt_rpc.urlopen", fake_urlopen)
    client_rpc = OpenWrtRPCClient("http://192.0.2.1", "openshield", "router-password")
    result = client_rpc.remove_firewall_block("os_abcdef1234567890")
    assert result["removed"] is True
    assert json.loads(requests[1].data)[2] == "delete"
    assert json.loads(requests[2].data)[2] == "apply"
    assert json.loads(requests[3].data)[3]["config"] == "firewall"
    assert json.loads(requests[4].data)[2] == "confirm"


def test_openwrt_rpc_rejects_private_ip_before_any_write(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(
        "openshield.integrations.openwrt_rpc.urlopen",
        lambda *args, **kwargs: calls.append(args),
    )
    client_rpc = OpenWrtRPCClient("http://192.0.2.1", "openshield", "router-password")
    with pytest.raises(ValueError, match="public IP"):
        client_rpc.apply_firewall_block("abcdef12-3456-7890", "192.168.1.1", "destination")
    assert calls == []


def test_policy_api_and_emergency_stop_fail_closed(monkeypatch) -> None:
    from openshield.api import main

    _register("pihole", "pihole-home")
    incident = _incident()
    policy_response = client.post("/api/v1/policies", json={
        "name": "Observe malicious domain",
        "indicator_type": "domain",
        "indicator_value": "malicious.example",
        "action": "block_domain",
        "integration_id": "pihole-home",
        "min_risk_score": 70,
        "autonomy_level": 0,
    })
    assert policy_response.status_code == 201
    evaluated = client.post(
        "/api/v1/incidents/" + incident["incident_id"] + "/evaluate",
        json={"policy_id": policy_response.json()["policy_id"]},
    )
    assert evaluated.status_code == 200
    assert evaluated.json()["status"] == "observe_only"
    stop = client.post("/api/v1/control/emergency-stop", json={"active": False})
    assert stop.status_code == 403
    assert main.store.get_emergency_stop() is True
