from datetime import UTC, datetime
from unittest.mock import patch

from fastapi.testclient import TestClient

from openshield.api.main import app
from openshield.integrations.models import Integration
from openshield.privacy.dns import classify_domain, normalize_dns_batch, normalize_domain
from openshield.privacy.providers import fetch_dns_records

client = TestClient(app)


def setup_function() -> None:
    from openshield.api import main
    main.store.reset()


def register_dns(integration_id: str = "pihole-home", kind: str = "pihole") -> None:
    response = client.post("/api/v1/integrations", json={
        "integration_id": integration_id,
        "kind": kind,
        "display_name": kind.title(),
        "config": {"base_url": "http://192.0.2.53"},
    })
    assert response.status_code == 201


def test_domain_normalization_and_classification() -> None:
    assert normalize_domain("  Ads.DoubleClick.NET. ") == "ads.doubleclick.net"
    assert classify_domain("metrics.google-analytics.com") == ("tracker", "high")
    assert classify_domain("payload.example.xyz") == ("suspicious_tld", "medium")
    assert classify_domain("example.org") == ("unclassified", "info")


def test_invalid_domain_and_ip_literal_are_rejected() -> None:
    for value in ["", "not a domain", "127.0.0.1", "-bad.example", "bad..example"]:
        try:
            normalize_domain(value)
        except ValueError:
            continue
        raise AssertionError(f"Expected invalid domain to be rejected: {value}")


def test_pihole_dns_queries_are_ingested_and_idempotent() -> None:
    register_dns()
    record = {
        "timestamp": datetime.now(UTC).isoformat(),
        "domain": "ads.doubleclick.net",
        "client": "192.168.1.20",
        "status": "blocked",
        "type": "A",
        "password": "must-not-be-stored",
    }
    url = "/api/v1/dns/pihole-home/queries"
    first = client.post(url, json=[record])
    second = client.post(url, json=[record])
    assert first.status_code == second.status_code == 202
    assert first.json() == {"accepted": 1, "duplicates": 0, "received": 1}
    assert second.json() == {"accepted": 0, "duplicates": 1, "received": 1}
    stored = client.get("/api/v1/events?event_type=privacy.dns.query").json()["items"]
    assert len(stored) == 1
    assert stored[0]["payload"]["category"] == "tracker"
    assert stored[0]["payload"]["status"] == "blocked"
    assert "password" not in stored[0]["payload"]


def test_adguard_dns_ingestion_and_provider_probe() -> None:
    register_dns("adguard-home", "adguard")
    probe = client.get("/api/v1/integrations/adguard-home/probe")
    assert probe.status_code == 200
    assert probe.json()["kind"] == "adguard"
    assert probe.json()["capabilities"] == [
        "health_check", "read_events", "read_configuration", "write_configuration",
    ]
    response = client.post("/api/v1/dns/adguard-home/queries", json=[{
        "time": datetime.now(UTC).isoformat(),
        "domain": "example.org",
        "client_ip": "192.168.1.21",
        "status": "processed",
        "qtype": "AAAA",
    }])
    assert response.status_code == 202
    assert response.json()["accepted"] == 1


def test_dns_batch_validation_and_unknown_integrations() -> None:
    register_dns()
    assert client.post("/api/v1/dns/pihole-home/queries", json=[{"domain": "invalid domain"}]).status_code == 422
    assert client.post("/api/v1/dns/missing/queries", json=[{"domain": "example.org"}]).status_code == 404
    try:
        normalize_dns_batch("pihole", "sensor", [])
    except ValueError as exc:
        assert "between 1 and 500" in str(exc)
    else:
        raise AssertionError("Empty DNS batch should be rejected")


def test_privacy_analytics_and_report_aggregate_queries() -> None:
    register_dns()
    records = [
        {"timestamp": datetime.now(UTC).isoformat(), "domain": "ads.doubleclick.net",
         "client": "192.168.1.20", "status": "blocked"},
        {"timestamp": datetime.now(UTC).isoformat(), "domain": "example.org",
         "client": "192.168.1.20", "status": "allowed"},
        {"timestamp": datetime.now(UTC).isoformat(), "domain": "ads.doubleclick.net",
         "client": "192.168.1.21", "status": "blocked"},
    ]
    assert client.post("/api/v1/dns/pihole-home/queries", json=records).status_code == 202
    domains = client.get("/api/v1/privacy/analytics/domains?days=30").json()
    assert domains[0]["domain"] == "ads.doubleclick.net"
    assert domains[0]["queries"] == 2
    assert domains[0]["blocked"] == 2
    devices = client.get("/api/v1/privacy/analytics/devices?days=30").json()
    assert devices[0]["client"] == "192.168.1.20"
    assert devices[0]["queries"] == 2
    report = client.get("/api/v1/privacy/report?days=30").json()
    assert report["totals"]["queries"] == 3
    assert report["totals"]["blocked"] == 2
    assert report["totals"]["block_rate_percent"] == 66.67
    assert report["totals"]["tracker_queries"] == 2
    assert len(report["daily_trends"]) == 1


def test_privacy_lists_are_normalized_persisted_and_audited() -> None:
    added = client.post("/api/v1/privacy/lists", json={
        "list_type": "block", "domain": "Ads.DoubleClick.NET.",
        "comment": "Known advertising tracker",
    })
    assert added.status_code == 201
    assert added.json()["domain"] == "ads.doubleclick.net"
    listed = client.get("/api/v1/privacy/lists").json()
    assert len(listed) == 1
    assert listed[0]["list_type"] == "block"
    assert client.delete("/api/v1/privacy/lists/block/ads.doubleclick.net").status_code == 204
    assert client.delete("/api/v1/privacy/lists/block/ads.doubleclick.net").status_code == 404
    audit = client.get("/api/v1/audit").json()
    assert any(item["action"] == "privacy.list.deleted" for item in audit)


def test_privacy_list_rejects_invalid_type_and_domain() -> None:
    assert client.post("/api/v1/privacy/lists", json={
        "list_type": "deny", "domain": "example.org",
    }).status_code == 422
    assert client.post("/api/v1/privacy/lists", json={
        "list_type": "allow", "domain": "not a domain",
    }).status_code == 422


def test_privacy_analytics_period_is_bounded() -> None:
    assert client.get("/api/v1/privacy/report?days=0").status_code == 422
    assert client.get("/api/v1/privacy/trends?days=366").status_code == 422



def test_privacy_source_health_reports_no_data_and_recent_ingestion() -> None:
    register_dns()
    assert client.get("/api/v1/privacy/sources").json()[0]["status"] == "no_data"
    response = client.post("/api/v1/dns/pihole-home/queries", json=[{
        "timestamp": datetime.now(UTC).isoformat(),
        "domain": "example.org",
        "client": "192.168.1.20",
    }])
    assert response.status_code == 202
    source = next(item for item in client.get("/api/v1/privacy/sources").json()
                   if item["integration_id"] == "pihole-home")
    assert source["status"] == "healthy"
    assert source["queries_seen"] == 1



def test_provider_sync_endpoint_ingests_pulled_records() -> None:
    register_dns()
    record = {
        "domain": "ads.doubleclick.net",
        "client": "192.168.1.22",
        "timestamp": datetime.now(UTC).isoformat(),
        "status": "blocked",
    }
    with patch("openshield.api.main.fetch_dns_records", return_value=[record]):
        response = client.post("/api/v1/privacy/sources/pihole-home/sync")
    assert response.status_code == 202
    assert response.json() == {"accepted": 1, "duplicates": 0, "received": 1}
    assert client.get("/api/v1/privacy/analytics/domains").json()[0]["domain"] == "ads.doubleclick.net"


def test_provider_sync_requires_registered_dns_source() -> None:
    assert client.post("/api/v1/privacy/sources/missing/sync").status_code == 404


def test_pihole_provider_client_authenticates_and_reads_query_log(monkeypatch) -> None:
    monkeypatch.setenv("OPENSHIELD_PIHOLE_PASSWORD", "provider-secret")
    responses = [
        b'{"session":{"sid":"test-session"}}',
        b'{"queries":[{"domain":"example.org","client":"192.168.1.2","timestamp":"2026-11-12T12:00:00Z","status":"FORWARDED","type":"A"}]}',
        b'{}',
    ]
    requests = []

    class FakeResponse:
        def __init__(self, payload):
            self.payload = payload

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, size):
            return self.payload

    def fake_urlopen(request, timeout):
        requests.append(request)
        return FakeResponse(responses.pop(0))

    with patch("openshield.privacy.providers.urlopen", side_effect=fake_urlopen):
        records = fetch_dns_records(Integration(
            integration_id="pihole-home", kind="pihole", display_name="Pi-hole",
            capabilities=[], config={"base_url": "http://192.0.2.53"},
        ))
    assert len(records) == 1
    assert records[0]["domain"] == "example.org"
    assert requests[1].get_header("X-ftl-sid") == "test-session"
    assert requests[2].get_method() == "DELETE"


def test_adguard_provider_client_uses_basic_auth_and_maps_query_log(monkeypatch) -> None:
    monkeypatch.setenv("OPENSHIELD_ADGUARD_USERNAME", "admin")
    monkeypatch.setenv("OPENSHIELD_ADGUARD_PASSWORD", "provider-secret")

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, size):
            return b'{"data":[{"question":{"host":"ads.doubleclick.net","type":"A"},"client":"192.168.1.3","time":"2026-11-12T12:00:00Z","reason":"FilteredBlackList","status":"NOERROR"}]}'

    captured = {}

    def fake_urlopen(request, timeout):
        captured["request"] = request
        return FakeResponse()

    with patch("openshield.privacy.providers.urlopen", side_effect=fake_urlopen):
        records = fetch_dns_records(Integration(
            integration_id="adguard-home", kind="adguard", display_name="AdGuard",
            capabilities=[], config={"base_url": "http://192.0.2.54"},
        ))
    assert records[0]["domain"] == "ads.doubleclick.net"
    assert records[0]["status"] == "FilteredBlackList"
    assert captured["request"].get_header("Authorization").startswith("Basic ")



def test_provider_list_sync_endpoint_is_explicit_and_audited() -> None:
    register_dns()
    client.post("/api/v1/privacy/lists", json={
        "list_type": "block", "domain": "ads.doubleclick.net",
    })
    with patch("openshield.api.main.sync_provider_lists", return_value={
        "provider": "pihole", "added": 1, "removed": 0,
    }):
        response = client.post("/api/v1/privacy/lists/pihole-home/sync")
    assert response.status_code == 200
    assert response.json()["entries"] == 1
    assert response.json()["added"] == 1
    audit = client.get("/api/v1/audit").json()
    assert any(item["action"] == "privacy.provider_lists.synchronized" for item in audit)


def test_pihole_list_sync_preserves_unmanaged_entries_and_verifies_changes(monkeypatch) -> None:
    from openshield.privacy.providers import sync_provider_lists

    monkeypatch.delenv("OPENSHIELD_PIHOLE_PASSWORD", raising=False)
    responses = [
        b'{"domains":[{"type":"deny","domain":"stale.example","comment":"OpenShield managed"},{"type":"deny","domain":"manual.example","comment":"User managed"}]}',
        b'{}',
        b'{}',
        b'{"domains":[{"type":"allow","domain":"allowed.example","comment":"OpenShield managed"},{"type":"deny","domain":"manual.example","comment":"User managed"}]}',
    ]
    requests = []

    class FakeResponse:
        def __init__(self, payload):
            self.payload = payload

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, size):
            return self.payload

    def fake_urlopen(request, timeout):
        requests.append(request)
        return FakeResponse(responses.pop(0))

    with patch("openshield.privacy.providers.urlopen", side_effect=fake_urlopen):
        result = sync_provider_lists(Integration(
            integration_id="pihole-home", kind="pihole", display_name="Pi-hole",
            capabilities=[], config={"base_url": "http://192.0.2.53"},
        ), [{"list_type": "allow", "domain": "allowed.example", "comment": ""}])
    assert result == {"provider": "pihole", "added": 1, "removed": 1}
    assert requests[1].get_method() == "POST"
    assert requests[2].get_method() == "DELETE"
    assert "manual.example" not in requests[2].full_url


def test_adguard_list_sync_preserves_existing_rules_and_verifies(monkeypatch) -> None:
    import json

    from openshield.privacy.providers import sync_provider_lists

    monkeypatch.delenv("OPENSHIELD_ADGUARD_USERNAME", raising=False)
    monkeypatch.delenv("OPENSHIELD_ADGUARD_PASSWORD", raising=False)
    expected_rules = [
        "||user.example^", "! OpenShield managed begin",
        "@@||allowed.example^", "||blocked.example^", "! OpenShield managed end",
    ]
    responses = [
        b'{"user_rules":["||user.example^"]}',
        b'{}',
        json.dumps({"user_rules": expected_rules}).encode(),
    ]
    requests = []

    class FakeResponse:
        def __init__(self, payload):
            self.payload = payload

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, size):
            return self.payload

    def fake_urlopen(request, timeout):
        requests.append(request)
        return FakeResponse(responses.pop(0))

    with patch("openshield.privacy.providers.urlopen", side_effect=fake_urlopen):
        result = sync_provider_lists(Integration(
            integration_id="adguard-home", kind="adguard", display_name="AdGuard",
            capabilities=[], config={"base_url": "http://192.0.2.54"},
        ), [
            {"list_type": "block", "domain": "blocked.example", "comment": ""},
            {"list_type": "allow", "domain": "allowed.example", "comment": ""},
        ])
    assert result == {"provider": "adguard", "added": 2, "removed": 0}
    payload = json.loads(requests[1].data)
    assert payload["rules"] == expected_rules


def test_dns_integration_connection_test_does_not_ingest_records() -> None:
    register_dns()
    record = {"domain": "example.org", "client": "192.168.1.20",
              "timestamp": datetime.now(UTC).isoformat(), "status": "allowed"}
    with patch("openshield.api.main.fetch_dns_records", return_value=[record]):
        response = client.post("/api/v1/integrations/pihole-home/test")
    assert response.status_code == 200
    assert response.json() == {
        "status": "connected", "integration_id": "pihole-home",
        "provider": "pihole", "records_available": 1, "imported": 0,
    }
    assert client.get("/api/v1/events?event_type=privacy.dns.query").json()["items"] == []


def test_dns_integration_connection_test_reports_provider_failure() -> None:
    from openshield.privacy.providers import DnsProviderError
    register_dns()
    with patch("openshield.api.main.fetch_dns_records", side_effect=DnsProviderError("unreachable")):
        response = client.post("/api/v1/integrations/pihole-home/test")
    assert response.status_code == 502
    assert response.json()["detail"] == "unreachable"


def test_sensor_integration_test_returns_push_endpoint() -> None:
    response = client.post("/api/v1/integrations", json={
        "integration_id": "suricata-home", "kind": "suricata", "display_name": "Suricata",
    })
    assert response.status_code == 201
    tested = client.post("/api/v1/integrations/suricata-home/test")
    assert tested.status_code == 200
    assert tested.json()["mode"] == "push"
    assert tested.json()["ingestion_endpoint"] == "/api/v1/sensors/suricata-home/events"


def test_background_dns_polling_ingests_enabled_sources_and_skips_disabled(monkeypatch) -> None:
    from openshield.api import main
    from openshield.privacy import polling

    register_dns("pihole-home", "pihole")
    register_dns("adguard-home", "adguard")
    disabled = client.patch("/api/v1/integrations/adguard-home", json={"enabled": False})
    assert disabled.status_code == 200
    record = {
        "timestamp": datetime.now(UTC).isoformat(),
        "domain": "ads.doubleclick.net",
        "client": "192.168.1.30",
        "status": "blocked",
    }
    calls = []

    def fake_fetch_page(integration, cursor):
        calls.append(integration.integration_id)
        return [record], {"watermark": 1, "complete": True}, True

    monkeypatch.setattr(polling, "fetch_dns_records_page", fake_fetch_page)

    class Metrics:
        def increment(self, name):
            assert name == "openshield_events_ingested_total"

    outcomes = polling.poll_dns_sources_once(main.registry, main.store, Metrics())
    assert calls == ["pihole-home"]
    assert outcomes == [{
        "integration_id": "pihole-home", "status": "ok",
        "received": 1, "accepted": 1, "duplicates": 0, "pages": 1, "complete": True,
    }]
    events = client.get("/api/v1/events?event_type=privacy.dns.query").json()["items"]
    assert len(events) == 1
    assert events[0]["payload"]["domain"] == "ads.doubleclick.net"
    source = next(item for item in client.get("/api/v1/privacy/sources").json()
                   if item["integration_id"] == "pihole-home")
    assert source["status"] == "healthy"
    assert source["last_success_at"]
    assert source["last_imported"] == 1
    assert any(item["action"] == "privacy.provider_poll.completed" for item in client.get("/api/v1/audit").json())



def test_background_dns_polling_records_provider_failure_and_continues(monkeypatch) -> None:
    from openshield.api import main
    from openshield.privacy import polling
    from openshield.privacy.providers import DnsProviderError

    register_dns("pihole-home", "pihole")
    register_dns("adguard-home", "adguard")
    calls = []

    def fake_fetch_page(integration, cursor):
        calls.append(integration.integration_id)
        if integration.integration_id == "pihole-home":
            raise DnsProviderError("provider unavailable")
        return [], {"watermark": 1, "complete": True}, True

    monkeypatch.setattr(polling, "fetch_dns_records_page", fake_fetch_page)

    class Metrics:
        def increment(self, name):
            raise AssertionError("No events should be ingested")

    outcomes = polling.poll_dns_sources_once(main.registry, main.store, Metrics())
    assert calls == ["adguard-home", "pihole-home"]
    assert outcomes == [
        {"integration_id": "adguard-home", "status": "ok", "received": 0, "accepted": 0, "duplicates": 0, "pages": 1, "complete": True},
        {"integration_id": "pihole-home", "status": "error"},
    ]
    audit = client.get("/api/v1/audit").json()
    assert any(item["action"] == "privacy.provider_poll.failed" for item in audit)
    assert any(item["action"] == "privacy.provider_poll.completed" for item in audit)
    sources = {item["integration_id"]: item for item in client.get("/api/v1/privacy/sources").json()}
    assert sources["pihole-home"]["status"] == "failed"
    assert sources["pihole-home"]["last_error"] == "Provider polling failed"



def test_disabled_dns_provider_cannot_be_manually_polled() -> None:
    register_dns()
    assert client.patch("/api/v1/integrations/pihole-home", json={"enabled": False}).status_code == 200
    assert client.post("/api/v1/privacy/sources/pihole-home/sync").status_code == 409
    source = client.get("/api/v1/privacy/sources").json()[0]
    assert source["status"] == "disabled"


def test_provider_poll_cursor_persists_and_cascades_with_integration() -> None:
    from openshield.api import main

    register_dns()
    state = {"watermark": 1234.5, "complete": True}
    main.store.set_integration_poll_cursor("pihole-home", "pihole", state)
    assert main.store.get_integration_poll_cursor("pihole-home") == state
    assert client.delete("/api/v1/integrations/pihole-home").status_code == 204
    assert main.store.get_integration_poll_cursor("pihole-home") is None


def test_pihole_query_log_pagination_uses_fixed_window_and_offset(monkeypatch) -> None:
    from openshield.privacy import providers

    integration = Integration(
        integration_id="pihole-home", kind="pihole", display_name="Pi-hole",
        capabilities=[], config={"base_url": "http://192.0.2.53"},
    )
    responses = [
        {"queries": [{"domain": "one.example", "timestamp": 1500},
                     {"domain": "two.example", "timestamp": 1499}]},
        {"queries": [{"domain": "three.example", "timestamp": 1498}]},
    ]
    requests = []

    def fake_request(base_url, path):
        requests.append(path)
        return responses.pop(0)

    monkeypatch.setattr(providers, "_pihole_request", fake_request)
    first, cursor, done = providers.fetch_dns_records_page(integration, page_size=2)
    assert len(first) == 2 and not done
    assert "start=0" in requests[0]
    second, final_cursor, done = providers.fetch_dns_records_page(integration, cursor, page_size=2)
    assert len(second) == 1 and done
    assert "start=2" in requests[1]
    assert final_cursor["complete"] is True
    assert cursor["window_until"] == final_cursor["watermark"]


def test_adguard_query_log_pagination_uses_older_than_watermark(monkeypatch) -> None:
    import json

    from openshield.privacy import providers

    integration = Integration(
        integration_id="adguard-home", kind="adguard", display_name="AdGuard",
        capabilities=[], config={"base_url": "http://192.0.2.54"},
    )
    responses = [
        {"oldest": "2026-11-13T12:00:01Z", "data": [
            {"question": {"host": "new.example"}, "time": "2026-11-13T12:00:02Z"},
            {"question": {"host": "mid.example"}, "time": "2026-11-13T12:00:01Z"},
        ]},
        {"oldest": "2026-11-13T11:59:59Z", "data": [
            {"question": {"host": "old.example"}, "time": "2026-11-13T11:59:59Z"},
        ]},
    ]
    requests = []

    class FakeResponse:
        def __init__(self, payload):
            self.payload = json.dumps(payload).encode()

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, size):
            return self.payload

    def fake_urlopen(request, timeout):
        requests.append(request.full_url)
        return FakeResponse(responses.pop(0))

    monkeypatch.setattr(providers, "urlopen", fake_urlopen)
    first, cursor, done = providers.fetch_dns_records_page(
        integration, {"watermark": datetime.fromisoformat("2026-11-13T12:00:00+00:00").timestamp()},
        page_size=2,
    )
    assert len(first) == 2 and not done
    second, final_cursor, done = providers.fetch_dns_records_page(integration, cursor, page_size=2)
    assert "older_than=2026-11-13T12%3A00%3A01Z" in requests[1]
    assert len(second) == 1 and done
    assert final_cursor["complete"] is True
