import asyncio
import json
import logging
from datetime import UTC, datetime
from unittest.mock import MagicMock

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from openshield.api.main import app
from openshield.core.secrets import SecretStore
from openshield.events.models import EventEnvelope, EventSource, Severity
from openshield.integrations.models import IntegrationRegistration
from openshield.threat_intel import engine, providers

client = TestClient(app)


def setup_function() -> None:
    from openshield.api import main

    main.store.reset()


def _response(payload: object) -> MagicMock:
    response = MagicMock()
    response.__enter__.return_value.read.return_value = json.dumps(payload).encode()
    return response


def _event(event_id: str = "suricata-event-1") -> EventEnvelope:
    now = datetime.now(UTC)
    return EventEnvelope(
        schema_version="openshield.event.v1",
        event_id=event_id,
        source=EventSource(integration_id="sensor-suricata", kind="suricata"),
        event_type="network.suricata.alert",
        occurred_at=now,
        observed_at=now,
        severity=Severity.HIGH,
        payload={
            "src_ip": "8.8.8.8",
            "dest_ip": "192.168.1.20",
            "dns": {"rrname": "example.com"},
        },
    )


def _register(kind: str, integration_id: str, config: dict | None = None) -> None:
    from openshield.api import main

    main.registry.register(IntegrationRegistration(
        integration_id=integration_id,
        kind=kind,
        display_name=integration_id,
        config=config or {},
    ))


def test_crowdsec_lookup_uses_cti_key_header_and_normalizes_reputation(monkeypatch) -> None:
    payload = {
        "ip": "8.8.8.8",
        "reputation": "malicious",
        "scores": {"overall": 80},
        "behaviors": [{"label": "ssh:bruteforce"}],
        "classifications": [{"label": "attackers"}],
    }
    requests = []

    def fake_urlopen(request, timeout):
        requests.append(request)
        assert timeout == 8
        return _response(payload)

    monkeypatch.setattr(providers, "urlopen", fake_urlopen)
    result = providers.lookup_crowdsec("8.8.8.8", "crowdsec-test-key")
    assert requests[0].full_url.endswith("/v2/smoke/8.8.8.8")
    assert requests[0].get_header("X-api-key") == "crowdsec-test-key"
    assert result["matched"] is True
    assert result["reputation"] == "malicious"
    assert result["score"] == 80
    assert result["behaviors"] == ["ssh:bruteforce"]


def test_crowdsec_rejects_private_and_invalid_addresses() -> None:
    import pytest

    with pytest.raises(ValueError, match="public IP"):
        providers.lookup_crowdsec("192.168.1.1", "key")
    with pytest.raises(ValueError, match="valid IP"):
        providers.lookup_crowdsec("not-an-ip", "key")


def test_misp_lookup_reuses_validated_client_and_shared_attribute_parser(monkeypatch) -> None:
    from openshield.integrations.misp import MispClient

    payload = {
        "response": [{
            "Attribute": {
                "id": "12", "type": "ip-src", "value": "8.8.8.8",
                "to_ids": True, "category": "Network activity", "timestamp": "1760000000",
                "Tag": [{"name": "tlp:green"}],
            },
            "Event": {"id": "42", "info": "Credential stuffing", "threat_level_id": "1"},
        }],
    }
    requests = []

    def fake_request(self, path, method, body=None):
        requests.append({
            "base_url": self._base_url,
            "api_key": self._api_key,
            "path": path,
            "method": method,
            "body": json.loads(body) if body else None,
        })
        return payload

    monkeypatch.setattr(MispClient, "_request", fake_request)
    result = providers.lookup_misp("https://misp.example", "misp-test-key", "ip", "8.8.8.8")

    assert requests == [{
        "base_url": "https://misp.example",
        "api_key": "misp-test-key",
        "path": "/attributes/restSearch",
        "method": "POST",
        "body": {"returnFormat": "json", "value": "8.8.8.8", "limit": 50, "page": 1},
    }]
    assert result["matched"] is True
    assert result["attributes"][0]["to_ids"] is True
    assert result["attributes"][0]["threat_level_id"] == 1
    assert result["attributes"][0]["tags"] == ["tlp:green"]


def test_indicator_extraction_ignores_private_addresses_and_normalizes_domains() -> None:
    indicators = engine.extract_indicators(_event())
    assert ("ip", "8.8.8.8") in indicators
    assert ("ip", "192.168.1.20") not in indicators
    assert ("domain", "example.com") in indicators


def test_enrichment_creates_incident_with_provenance_cache_and_false_positive_state(monkeypatch) -> None:
    from openshield.api import main

    monkeypatch.setenv("OPENSHIELD_SECRET_KEY", Fernet.generate_key().decode())
    _register("suricata", "sensor-suricata")
    _register("crowdsec", "crowdsec-home")
    _register("misp", "misp-home", {"base_url": "https://misp.example"})
    SecretStore(main.store).set("crowdsec-home", {"api_key": "crowdsec-key"})
    SecretStore(main.store).set("misp-home", {"api_key": "misp-key"})
    event = _event()
    main.store.insert_event(event)
    calls = {"crowdsec": 0, "misp": 0}

    def crowdsec(ip_value, api_key):
        calls["crowdsec"] += 1
        return {
            "provider": "crowdsec", "indicator_type": "ip",
            "indicator_value": ip_value, "matched": True,
            "reputation": "malicious", "score": 80,
        }

    def misp(base_url, api_key, indicator_type, indicator_value):
        calls["misp"] += 1
        return {
            "provider": "misp", "indicator_type": indicator_type,
            "indicator_value": indicator_value, "matched": False, "attributes": [],
        }

    monkeypatch.setattr(engine, "lookup_crowdsec", crowdsec)
    monkeypatch.setattr(engine, "lookup_misp", misp)
    result = engine.enrich_events(main.store, main.registry, [event.event_id])
    assert len(result["incidents"]) == 1
    incident = result["incidents"][0]
    assert incident["indicator_value"] == "8.8.8.8"
    assert incident["risk_score"] >= 60
    assert "crowdsec-home" in incident["sources"]
    assert incident["intel_evidence"]["crowdsec-home"]["reputation"] == "malicious"
    assert main.store.get_incident_events(incident["incident_id"])[0].event_id == event.event_id
    assert calls["crowdsec"] == 1

    main.store.update_incident_status(incident["incident_id"], "false_positive", "Known benign test fixture")
    second_event = _event("suricata-event-2")
    main.store.insert_event(second_event)
    repeated = engine.enrich_events(main.store, main.registry, [second_event.event_id])
    assert repeated["incidents"][0]["status"] == "false_positive"
    assert set(repeated["incidents"][0]["event_ids"]) == {event.event_id, second_event.event_id}
    assert len(main.store.get_incident_events(incident["incident_id"])) == 2
    assert calls["crowdsec"] == 1  # cache prevents another paid/provider lookup


def test_incident_api_supports_evidence_timeline_and_false_positive_audit(monkeypatch) -> None:
    from openshield.api import main

    monkeypatch.setenv("OPENSHIELD_SECRET_KEY", Fernet.generate_key().decode())
    _register("suricata", "sensor-suricata")
    _register("crowdsec", "crowdsec-home")
    SecretStore(main.store).set("crowdsec-home", {"api_key": "crowdsec-key"})
    event = _event("api-event-1")
    main.store.insert_event(event)
    monkeypatch.setattr(engine, "lookup_crowdsec", lambda ip_value, api_key: {
        "provider": "crowdsec", "indicator_type": "ip",
        "indicator_value": ip_value, "matched": True, "reputation": "malicious", "score": 90,
    })
    enriched = client.post("/api/v1/threat-intel/enrich", json={"event_ids": [event.event_id]})
    assert enriched.status_code == 200
    incident = enriched.json()["incidents"][0]
    detail = client.get("/api/v1/incidents/" + incident["incident_id"])
    assert detail.status_code == 200
    assert detail.json()["timeline"][0]["event_id"] == event.event_id
    updated = client.patch(
        "/api/v1/incidents/" + incident["incident_id"],
        json={"status": "false_positive", "reason": "Validated benign"},
    )
    assert updated.status_code == 200
    assert updated.json()["status"] == "false_positive"
    assert any(
        item["action"] == "incident.status.updated"
        for item in client.get("/api/v1/audit").json()
    )


def test_threat_intel_credentials_are_redacted_and_legacy_connection_test_is_rejected(monkeypatch) -> None:
    monkeypatch.setenv("OPENSHIELD_SECRET_KEY", Fernet.generate_key().decode())
    _register("crowdsec", "crowdsec-home")
    response = client.put(
        "/api/v1/integrations/crowdsec-home/threat-intel-credentials",
        json={"api_key": "very-secret-crowdsec-key"},
    )
    assert response.status_code == 200
    assert "very-secret-crowdsec-key" not in response.text
    assert "very-secret-crowdsec-key" not in str(client.get("/api/v1/integrations").json())
    tested = client.post("/api/v1/integrations/crowdsec-home/test")
    assert tested.status_code == 409
    assert tested.json()["detail"] == (
        "CrowdSec Local API bouncer credentials are not configured"
    )


def test_enrichment_limits_unique_indicators_to_fifty(monkeypatch) -> None:
    from openshield.api import main

    monkeypatch.setenv("OPENSHIELD_SECRET_KEY", Fernet.generate_key().decode())
    _register("suricata", "sensor-suricata")
    _register("crowdsec", "crowdsec-home")
    SecretStore(main.store).set("crowdsec-home", {"api_key": "crowdsec-key"})
    events = []
    for index in range(60):
        event = _event(f"batch-event-{index}")
        event = event.model_copy(update={"payload": {"src_ip": f"8.8.{index // 250}.{index % 250 + 1}"}})
        main.store.insert_event(event)
        events.append(event.event_id)
    calls = []
    monkeypatch.setattr(engine, "lookup_crowdsec", lambda ip, key: (
        calls.append(ip) or {
            "provider": "crowdsec", "indicator_type": "ip", "indicator_value": ip,
            "matched": False, "reputation": "unknown",
        }
    ))
    result = engine.enrich_events(main.store, main.registry, events)
    assert result["indicators_considered"] == 50
    assert result["indicators_truncated"] == 10
    assert len(calls) == 50


def test_expired_threat_intel_cache_is_deleted_in_bounded_batches() -> None:
    from openshield.api import main

    store = main.store
    store.set_threat_intel_cache("cleanup-test", "ip", "198.51.100.1", {"expired": 1})
    store.set_threat_intel_cache("cleanup-test", "ip", "198.51.100.2", {"expired": 2})
    store.set_threat_intel_cache("cleanup-test", "ip", "198.51.100.3", {"active": 3})
    with store._connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            """
            UPDATE threat_intel_cache
            SET expires_at = NOW() - INTERVAL '1 minute'
            WHERE provider = %s AND indicator_value IN (%s, %s)
            """,
            ("cleanup-test", "198.51.100.1", "198.51.100.2"),
        )

    assert store.expire_threat_intel_cache(limit=1) == 1
    assert store.get_threat_intel_cache("cleanup-test", "ip", "198.51.100.3") == {"active": 3}
    with store._connect() as connection, connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT COUNT(*) FROM threat_intel_cache
            WHERE provider = %s AND expires_at <= NOW()
            """,
            ("cleanup-test",),
        )
        assert cursor.fetchone()[0] == 1

    assert store.expire_threat_intel_cache(limit=1) == 1
    assert store.get_threat_intel_cache("cleanup-test", "ip", "198.51.100.3") == {"active": 3}


def test_expiration_worker_runs_bounded_cache_cleanup_and_logs(
    monkeypatch, caplog,
) -> None:
    from openshield.execution import worker

    class FakeStore:
        def __init__(self) -> None:
            self.limits: list[int] = []

        def expire_threat_intel_cache(self, limit: int) -> int:
            self.limits.append(limit)
            return 3

    store = FakeStore()
    monkeypatch.setattr(worker, "expire_due_executions", lambda *_args: None)

    async def stop_after_first_cycle(_seconds: int) -> None:
        raise asyncio.CancelledError

    monkeypatch.setattr(worker.asyncio, "sleep", stop_after_first_cycle)
    caplog.set_level(logging.INFO, logger="openshield.execution.worker")

    try:
        asyncio.run(worker.run_expiration_loop(store, MagicMock(), interval_seconds=1))
    except asyncio.CancelledError:
        pass

    assert store.limits == [500]
    assert "Expired threat intelligence cache entries deleted count=3" in caplog.text

 
 
def test_invalid_indicator_does_not_disable_provider_for_remaining_indicators(monkeypatch) -> None:
    from openshield.api import main
    from openshield.threat_intel.providers import ThreatIntelIndicatorError

    monkeypatch.setenv("OPENSHIELD_SECRET_KEY", Fernet.generate_key().decode())
    _register("suricata", "sensor-suricata")
    _register("crowdsec", "crowdsec-home")
    SecretStore(main.store).set("crowdsec-home", {"api_key": "crowdsec-key"})
    event = _event("mixed-indicator-event").model_copy(update={
        "payload": {"src_ip": "8.8.8.8", "dest_ip": "1.1.1.1"},
    })
    main.store.insert_event(event)
    calls: list[str] = []

    def lookup(ip_value: str, _api_key: str) -> dict[str, object]:
        calls.append(ip_value)
        if ip_value == "8.8.8.8":
            raise ThreatIntelIndicatorError("invalid test indicator")
        return {
            "provider": "crowdsec",
            "indicator_type": "ip",
            "indicator_value": ip_value,
            "matched": True,
            "reputation": "malicious",
            "score": 80,
        }

    monkeypatch.setattr(engine, "lookup_crowdsec", lookup)
    result = engine.enrich_events(main.store, main.registry, [event.event_id])

    assert calls == ["8.8.8.8", "1.1.1.1"]
    assert [item["indicator_value"] for item in result["incidents"]] == ["1.1.1.1"]
    assert result["errors"] == [{
        "integration_id": "crowdsec-home",
        "error": "invalid_indicator",
        "scope": "indicator",
    }]


def test_provider_failure_stops_remaining_lookups_for_that_provider(monkeypatch) -> None:
    from openshield.api import main

    monkeypatch.setenv("OPENSHIELD_SECRET_KEY", Fernet.generate_key().decode())
    _register("suricata", "sensor-suricata")
    _register("crowdsec", "crowdsec-home")
    SecretStore(main.store).set("crowdsec-home", {"api_key": "crowdsec-key"})
    event = _event("provider-failure-event").model_copy(update={
        "payload": {"src_ip": "8.8.8.8", "dest_ip": "1.1.1.1"},
    })
    main.store.insert_event(event)
    calls: list[str] = []

    def unavailable(ip_value: str, _api_key: str) -> dict[str, object]:
        calls.append(ip_value)
        raise providers.ThreatIntelProviderError("provider unavailable")

    monkeypatch.setattr(engine, "lookup_crowdsec", unavailable)
    result = engine.enrich_events(main.store, main.registry, [event.event_id])

    assert calls == ["8.8.8.8"]
    assert result["errors"] == [{
        "integration_id": "crowdsec-home",
        "error": "provider_lookup_failed",
        "scope": "provider",
    }]
