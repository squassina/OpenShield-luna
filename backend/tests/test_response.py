from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from openshield.api.main import app
from openshield.events.models import EventEnvelope, EventSource, Severity
from openshield.integrations.models import IntegrationRegistration
from openshield.response import engine

client = TestClient(app)


def setup_function() -> None:
    from openshield.api import main

    main.store.reset()


def _register_provider() -> None:
    from openshield.api import main

    main.registry.register(IntegrationRegistration(
        integration_id="pihole-home",
        kind="pihole",
        display_name="Home Pi-hole",
        config={"base_url": "http://192.0.2.53"},
    ))


def _create_incident(
    incident_id: str = "incident-domain-1",
    domain: str = "bad.example",
    risk_score: int = 70,
    indicator_type: str = "domain",
) -> str:
    from openshield.api import main

    if main.registry.get("sensor-suricata") is None:
        main.registry.register(IntegrationRegistration(
            integration_id="sensor-suricata",
            kind="suricata",
            display_name="Suricata",
        ))
    now = datetime.now(UTC)
    event = EventEnvelope(
        schema_version="openshield.event.v1",
        event_id="event-" + incident_id,
        source=EventSource(integration_id="sensor-suricata", kind="suricata"),
        event_type="network.suricata.alert",
        occurred_at=now,
        observed_at=now,
        severity=Severity.HIGH,
        payload={"domain": domain},
    )
    main.store.insert_event(event)
    main.store.upsert_incident(
        {
            "incident_id": incident_id,
            "indicator_type": indicator_type,
            "indicator_value": domain,
            "title": "Threat intelligence match",
            "summary": "Test incident",
            "risk_score": risk_score,
            "risk_level": "critical" if risk_score >= 80 else "high",
            "status": "open",
            "sources": ["misp-home"],
            "risk_factors": [{"factor": "test", "points": risk_score}],
            "source_events": [],
            "intel_evidence": {},
            "first_seen_at": now.isoformat(),
            "last_seen_at": now.isoformat(),
            "created_at": now.isoformat(),
        },
        [event.event_id],
        now,
        now,
    )
    return incident_id


def _create_policy(*, approval_required: bool = False, ttl_seconds: int = 3600) -> str:
    response = client.post("/api/v1/response/policies", json={
        "name": "Block high-risk domains",
        "provider_integration_id": "pihole-home",
        "action_type": "dns_block_domain",
        "min_risk_score": 60,
        "ttl_seconds": ttl_seconds,
        "approval_required": approval_required,
        "enabled": True,
    })
    assert response.status_code == 201
    return response.json()["policy_id"]


def _fake_sync(provider, entries):
    return {
        "provider": provider.kind,
        "added": sum(item["list_type"] == "block" for item in entries),
        "removed": 0,
    }


def test_response_policy_auto_executes_dns_block_and_supports_rollback(monkeypatch) -> None:
    from openshield.api import main

    _register_provider()
    incident_id = _create_incident()
    _create_policy()
    monkeypatch.setattr(engine, "sync_provider_lists", _fake_sync)

    evaluated = client.post(f"/api/v1/incidents/{incident_id}/response/evaluate")
    assert evaluated.status_code == 200
    action = evaluated.json()["actions"][0]
    assert action["status"] == "active"
    assert action["verification"]["readback_verified"] is True
    assert action["expires_at_display"]
    entries = main.store.list_privacy_lists("openshield-local")
    assert entries[0]["domain"] == "bad.example"
    assert entries[0]["comment"] == "OpenShield response:" + action["action_id"]

    rolled_back = client.post(f"/api/v1/response/actions/{action['action_id']}/rollback")
    assert rolled_back.status_code == 200
    assert rolled_back.json()["status"] == "rolled_back"
    assert main.store.list_privacy_lists("openshield-local") == []


def test_critical_incident_requires_human_approval_even_for_auto_policy(monkeypatch) -> None:
    _register_provider()
    incident_id = _create_incident("incident-critical", "critical.example", 90)
    _create_policy(approval_required=False)
    calls = []
    monkeypatch.setattr(engine, "sync_provider_lists", lambda provider, entries: calls.append(entries) or _fake_sync(provider, entries))

    evaluated = client.post(f"/api/v1/incidents/{incident_id}/response/evaluate")
    action = evaluated.json()["actions"][0]
    assert action["status"] == "pending_approval"
    assert calls == []

    approved = client.post(f"/api/v1/response/actions/{action['action_id']}/approve")
    assert approved.status_code == 200
    assert approved.json()["status"] == "active"
    assert len(calls) == 1


def test_kill_switch_rolls_back_active_actions_and_blocks_new_execution(monkeypatch) -> None:
    from openshield.api import main

    _register_provider()
    incident_id = _create_incident("incident-before-kill", "before-kill.example")
    _create_policy()
    monkeypatch.setattr(engine, "sync_provider_lists", _fake_sync)
    action = client.post(f"/api/v1/incidents/{incident_id}/response/evaluate").json()["actions"][0]
    assert action["status"] == "active"

    stopped = client.put("/api/v1/response/control", json={
        "enabled": True, "reason": "Emergency stop test",
    })
    assert stopped.status_code == 200
    assert stopped.json()["kill_switch_enabled"] is True
    assert stopped.json()["rolled_back"] == 1
    assert main.store.get_response_action(action["action_id"])["status"] == "rolled_back"
    assert main.store.list_privacy_lists("openshield-local") == []

    next_incident = _create_incident("incident-after-kill", "after-kill.example")
    blocked = client.post(f"/api/v1/incidents/{next_incident}/response/evaluate")
    assert blocked.status_code == 200
    assert blocked.json()["actions"][0]["status"] == "blocked_by_kill_switch"
    assert main.store.list_privacy_lists("openshield-local") == []


def test_response_ttl_worker_retries_provider_rollback_failure(monkeypatch) -> None:
    from openshield.api import main

    _register_provider()
    incident_id = _create_incident("incident-ttl", "ttl.example")
    _create_policy()
    monkeypatch.setattr(engine, "sync_provider_lists", _fake_sync)
    action = client.post(f"/api/v1/incidents/{incident_id}/response/evaluate").json()["actions"][0]
    stored = main.store.get_response_action(action["action_id"])
    expired_at = datetime.now(UTC) - timedelta(seconds=1)
    main.store.update_response_action(
        action["action_id"], stored, expires_at=expired_at, next_attempt_at=None,
    )

    calls = {"count": 0}

    def fail_once(provider, entries):
        calls["count"] += 1
        if calls["count"] == 1:
            from openshield.privacy.providers import DnsProviderError
            raise DnsProviderError("provider unavailable")
        return _fake_sync(provider, entries)

    monkeypatch.setattr(engine, "sync_provider_lists", fail_once)
    first = engine.expire_due_actions(main.store, main.registry)
    assert first["rollback_pending"] == 1
    pending = main.store.get_response_action(action["action_id"])
    assert pending["status"] == "rollback_pending"
    assert main.store.list_privacy_lists("openshield-local")

    main.store.update_response_action(
        action["action_id"], pending, expires_at=expired_at,
        next_attempt_at=datetime.now(UTC) - timedelta(seconds=1),
        attempts=int(pending.get("attempts", 0)),
    )
    second = engine.expire_due_actions(main.store, main.registry)
    assert second["expired"] == 1
    assert main.store.get_response_action(action["action_id"])["status"] == "rolled_back"
    assert main.store.list_privacy_lists("openshield-local") == []


def test_response_policy_rejects_unsupported_provider_and_bounds_ttl() -> None:
    _register_provider()
    invalid_provider = client.post("/api/v1/response/policies", json={
        "name": "Bad", "provider_integration_id": "missing-provider",
        "min_risk_score": 50, "ttl_seconds": 60,
    })
    assert invalid_provider.status_code == 422
    invalid_ttl = client.post("/api/v1/response/policies", json={
        "name": "Bad TTL", "provider_integration_id": "pihole-home",
        "min_risk_score": 50, "ttl_seconds": 10,
    })
    assert invalid_ttl.status_code == 422


def test_firewall_policy_requires_approval_and_executes_through_gateway(monkeypatch) -> None:
    from cryptography.fernet import Fernet

    from openshield.api import main

    monkeypatch.setenv("OPENSHIELD_SECRET_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("OPENSHIELD_GATEWAY_TOKEN", "gateway-test-token")
    _create_incident("incident-ip-1", "8.8.8.8", 75, indicator_type="ip")

    gateway_headers = {"Authorization": "Bearer gateway-test-token"}
    connected = client.post("/api/v1/gateway/connect", headers=gateway_headers, json={
        "protocol_version": "openshield.gateway.v1",
        "gateway_id": "home-gateway",
        "gateway_type": "openwrt",
        "connector_version": "0.1.0",
        "capabilities": ["discover", "health_check", "execute_action", "verify_action"],
    })
    assert connected.status_code == 201
    credentials = client.put(
        "/api/v1/integrations/home-gateway/openwrt-credentials",
        headers=gateway_headers,
        json={"base_url":"https://192.0.2.1","username":"rpc","password":"router-secret"},
    )
    assert credentials.status_code == 200

    policy = client.post("/api/v1/response/policies", json={
        "name":"Block malicious public IP",
        "provider_integration_id":"home-gateway",
        "action_type":"firewall_block_ip",
        "min_risk_score":60,
        "ttl_seconds":300,
        "approval_required":False,
        "enabled":True,
    })
    assert policy.status_code == 201
    evaluated = client.post("/api/v1/incidents/incident-ip-1/response/evaluate")
    action = evaluated.json()["actions"][0]
    assert action["status"] == "pending_approval"
    approved = client.post(f"/api/v1/response/actions/{action['action_id']}/approve")
    assert approved.status_code == 200
    assert approved.json()["status"] == "queued"

    heartbeat = client.post(
        "/api/v1/gateway/heartbeat", headers=gateway_headers,
        json={"protocol_version":"openshield.gateway.v1","gateway_id":"home-gateway"},
    )
    assert heartbeat.status_code == 200
    assert heartbeat.json()["pending_actions"][0]["action_id"] == action["action_id"]
    invalid_evidence = client.post(
        f"/api/v1/gateway/actions/{action['action_id']}/result",
        headers=gateway_headers,
        json={"gateway_id":"home-gateway","status":"active","result":{"status":"blocked","ip":"1.1.1.1"}},
    )
    assert invalid_evidence.status_code == 422
    applied = client.post(
        f"/api/v1/gateway/actions/{action['action_id']}/result",
        headers=gateway_headers,
        json={
            "gateway_id":"home-gateway","status":"active",
            "result":{"status":"blocked","ip":"8.8.8.8","ttl_seconds":300},
        },
    )
    assert applied.status_code == 200
    assert applied.json()["status"] == "active"

    stopped = client.put("/api/v1/response/control", json={
        "enabled":True,"reason":"Emergency stop firewall test",
    })
    assert stopped.status_code == 200
    assert stopped.json()["rollback_pending"] == 1
    rollback_heartbeat = client.post(
        "/api/v1/gateway/heartbeat", headers=gateway_headers,
        json={"protocol_version":"openshield.gateway.v1","gateway_id":"home-gateway"},
    )
    assert rollback_heartbeat.json()["pending_actions"][0]["status"] == "rollback_queued"
    rolled_back = client.post(
        f"/api/v1/gateway/actions/{action['action_id']}/result",
        headers=gateway_headers,
        json={"gateway_id":"home-gateway","status":"rolled_back","result":{"status":"unblocked"}},
    )
    assert rolled_back.status_code == 200
    assert rolled_back.json()["status"] == "rolled_back"
    assert main.store.get_response_action(action["action_id"])["status"] == "rolled_back"
