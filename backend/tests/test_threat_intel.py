import json
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


def test_misp_lookup_uses_rest_search_and_extracts_actionable_ioc(monkeypatch) -> None:
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

    def fake_urlopen(request, timeout):
        requests.append(request)
        return _response(payload)

    monkeypatch.setattr(providers, "urlopen", fake_urlopen)
    result = providers.lookup_misp("https://misp.example", "misp-test-key", "ip", "8.8.8.8")
    assert requests[0].full_url == "https://misp.example/attributes/restSearch"
    assert requests[0].get_header("Authorization") == "misp-test-key"
    assert json.loads(requests[0].data) == {
        "returnFormat": "json", "value": "8.8.8.8", "limit": 50, "page": 1,
    }
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
    repeated = engine.enrich_events(main.store, main.registry, [event.event_id])
    assert repeated["incidents"][0]["status"] == "false_positive"
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


def test_threat_intel_credentials_are_redacted_and_connection_test_is_explicit(monkeypatch) -> None:
    from openshield.api import main

    monkeypatch.setenv("OPENSHIELD_SECRET_KEY", Fernet.generate_key().decode())
    _register("crowdsec", "crowdsec-home")
    response = client.put(
        "/api/v1/integrations/crowdsec-home/threat-intel-credentials",
        json={"api_key": "very-secret-crowdsec-key"},
    )
    assert response.status_code == 200
    assert "very-secret-crowdsec-key" not in response.text
    assert "very-secret-crowdsec-key" not in str(client.get("/api/v1/integrations").json())
    monkeypatch.setattr(main, "lookup_crowdsec", lambda ip, key: {"matched": False})
    tested = client.post("/api/v1/integrations/crowdsec-home/test")
    assert tested.status_code == 200
    assert tested.json()["status"] == "connected"
