from datetime import UTC, datetime
from unittest.mock import patch

import pytest
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
    with patch("openshield.api.routers.privacy.fetch_dns_records", return_value=[record]):
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



def test_provider_list_sync_merges_manual_and_provider_scoped_entries() -> None:
    register_dns()
    client.post("/api/v1/privacy/lists", json={
        "list_type": "block", "domain": "manual.example", "comment": "Manual entry",
    })
    from openshield.api import main

    main.store.upsert_privacy_list(
        "pihole-home", "block", "p5-managed.example", "OpenShield managed execution test",
    )
    captured = []
    def fake_sync(integration, entries, credentials=None):
        captured.extend(dict(entry) for entry in entries)
        return {"provider": "pihole", "added": 2, "removed": 0}

    with patch("openshield.api.routers.privacy.sync_provider_lists", side_effect=fake_sync):
        response = client.post("/api/v1/privacy/lists/pihole-home/sync")
        repeated = client.post("/api/v1/privacy/lists/pihole-home/sync")
        deleted = client.delete("/api/v1/privacy/lists/block/manual.example")
        after_delete = client.post("/api/v1/privacy/lists/pihole-home/sync")
    assert response.status_code == repeated.status_code == after_delete.status_code == 200
    assert response.json()["entries"] == repeated.json()["entries"] == 2
    assert deleted.status_code == 204
    assert {(item["domain"], item["list_type"]) for item in captured[:2]} == {
        ("manual.example", "block"),
        ("p5-managed.example", "block"),
    }
    assert {(item["domain"], item["list_type"]) for item in captured[2:4]} == {
        ("manual.example", "block"),
        ("p5-managed.example", "block"),
    }
    assert captured[4]["domain"] == "p5-managed.example"
    assert len(captured) == 5
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
    with patch("openshield.api.routers.integration_tests.fetch_dns_records", return_value=[record]):
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
    with patch("openshield.api.routers.integration_tests.fetch_dns_records", side_effect=DnsProviderError("unreachable")):
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

    from openshield.core.metrics import MetricsRegistry

    metrics = MetricsRegistry()
    outcomes = polling.poll_dns_sources_once(main.registry, main.store, metrics)
    assert calls == ["pihole-home"]
    assert outcomes == [{
        "integration_id": "pihole-home", "status": "ok",
        "received": 1, "accepted": 1, "duplicates": 0, "rejected": 0,
        "pages": 1, "complete": True,
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

    from openshield.core.metrics import MetricsRegistry

    metrics = MetricsRegistry()
    outcomes = polling.poll_dns_sources_once(main.registry, main.store, metrics)
    assert calls == ["adguard-home", "pihole-home"]
    assert outcomes == [
        {"integration_id": "adguard-home", "status": "ok", "received": 0, "accepted": 0, "duplicates": 0,
         "rejected": 0, "pages": 1, "complete": True},
        {"integration_id": "pihole-home", "status": "error", "category": "provider_error"},
    ]
    audit = client.get("/api/v1/audit").json()
    assert any(item["action"] == "privacy.provider_poll.failed" for item in audit)
    assert any(item["action"] == "privacy.provider_poll.completed" for item in audit)
    sources = {item["integration_id"]: item for item in client.get("/api/v1/privacy/sources").json()}
    assert sources["pihole-home"]["status"] == "failed"
    assert sources["pihole-home"]["last_error"] == "DNS provider request failed"
    assert sources["pihole-home"]["last_error_category"] == "provider_error"
    assert sources["pihole-home"]["retryable"] is True
    assert sources["pihole-home"]["last_failure_at"]
    rendered = metrics.render()
    assert 'openshield_dns_poll_failures_total{category="provider_error",provider="pihole"} 1' in rendered
    assert 'openshield_dns_poll_success_total{provider="adguard"} 1' in rendered



def test_disabled_dns_provider_cannot_be_manually_polled() -> None:
    register_dns()
    assert client.patch("/api/v1/integrations/pihole-home", json={"enabled": False}).status_code == 200
    assert client.post("/api/v1/privacy/sources/pihole-home/sync").status_code == 409
    source = client.get("/api/v1/privacy/sources").json()[0]
    assert source["status"] == "disabled"
    assert any(
        item["action"] == "integration.ingestion.rejected"
        and item["target_id"] == "pihole-home"
        and item["details"] == {
            "source": "dns_manual_sync", "reason": "integration_disabled",
        }
        for item in client.get("/api/v1/audit").json()
    )


def test_disabled_dns_integration_rejects_direct_ingestion_and_audits() -> None:
    register_dns()
    assert client.patch(
        "/api/v1/integrations/pihole-home", json={"enabled": False}
    ).status_code == 200

    response = client.post("/api/v1/dns/pihole-home/queries", json=[{}])
    assert response.status_code == 409
    assert response.json()["detail"] == "Integration is disabled; new ingestion is rejected"
    assert client.get("/api/v1/events").json()["items"] == []
    assert any(
        item["action"] == "integration.ingestion.rejected"
        and item["target_id"] == "pihole-home"
        and item["details"] == {
            "source": "dns_queries", "reason": "integration_disabled",
        }
        for item in client.get("/api/v1/audit").json()
    )


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

    def fake_request(base_url, path, integration=None):
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


def test_adguard_expired_pagination_cursor_is_reported_without_advancing(monkeypatch) -> None:
    import json

    from openshield.privacy import providers
    from openshield.privacy.providers import DnsProviderCursorExpired

    integration = Integration(
        integration_id="adguard-home", kind="adguard", display_name="AdGuard",
        capabilities=[], config={"base_url": "http://192.0.2.54"},
    )

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, size):
            return json.dumps({"oldest": "", "data": []}).encode()

    monkeypatch.setattr(providers, "urlopen", lambda request, timeout: FakeResponse())
    try:
        providers.fetch_dns_records_page(
            integration, {"watermark": 1, "older_than": "2026-11-13T00:00:00Z"},
        )
    except DnsProviderCursorExpired as exc:
        assert "retention expired" in str(exc)
    else:
        raise AssertionError("Expired provider cursor must not silently advance")


def test_dns_provider_cursor_can_be_reset_and_is_audited() -> None:
    from openshield.api import main

    register_dns("adguard-home", "adguard")
    main.store.set_integration_poll_cursor(
        "adguard-home", "adguard", {"watermark": 1, "complete": True},
    )
    response = client.delete("/api/v1/privacy/sources/adguard-home/cursor")
    assert response.status_code == 200
    assert response.json()["status"] == "reset"
    assert main.store.get_integration_poll_cursor("adguard-home") is None
    assert any(
        item["action"] == "privacy.provider_poll.cursor_reset"
        for item in client.get("/api/v1/audit").json()
    )


def test_classification_metadata_uses_pinned_adguard_feed() -> None:
    from openshield.privacy.dns import CNAME_TRACKER_METADATA, classify_domain_metadata

    direct = classify_domain_metadata("api.clickaine.com")
    assert direct["category"] == "unclassified"
    result = classify_domain_metadata("news.example.com", cname_targets=["api.clickaine.com"])
    assert result["category"] == "tracker"
    assert result["source"] == "adguard_cname_trackers"
    assert result["version"] == CNAME_TRACKER_METADATA["source_commit"]
    assert result["confidence"] == 0.98
    assert result["matched_cname_target"] == "api.clickaine.com"


def test_allow_override_precedes_tracker_classification_without_changing_dns_evidence() -> None:
    overrides = {
        "google-analytics.com": {
            "action": "allow", "reason": "Approved analytics", "updated_at": "2026-11-13T10:00:00+00:00",
        },
    }
    events = normalize_dns_batch("pihole", "pihole-home", [{
        "domain": "metrics.google-analytics.com", "client": "192.168.1.30",
        "timestamp": datetime.now(UTC).isoformat(), "status": "blocked",
    }], classification_overrides=overrides)
    payload = events[0].payload
    assert payload["category"] == "allowed_override"
    assert payload["classification"]["source"] == "user_override"
    assert payload["classification"]["confidence"] == 1.0
    assert payload["domain"] == "metrics.google-analytics.com"
    assert payload["status"] == "blocked"


def test_classification_override_api_persists_and_audits() -> None:
    response = client.put(
        "/api/v1/privacy/classifications/overrides/example.com",
        json={"action": "allow", "reason": "Approved by household"},
    )
    assert response.status_code == 200
    assert response.json()["action"] == "allow"
    listed = client.get("/api/v1/privacy/classifications/overrides").json()
    assert listed["example.com"]["reason"] == "Approved by household"
    assert client.delete("/api/v1/privacy/classifications/overrides/example.com").status_code == 204
    assert any(
        item["action"] == "privacy.classification_override.updated"
        for item in client.get("/api/v1/audit").json()
    )


def test_adguard_normalizer_preserves_observed_cname_targets(monkeypatch) -> None:
    from openshield.privacy import providers

    normalized = providers._normalize_adguard_records([{
        "question": {"host": "news.example.com", "type": "A"},
        "time": "2026-11-13T10:00:00Z",
        "answer": [
            {"type": "CNAME", "value": "api.clickaine.com"},
            {"type": "A", "value": "192.0.2.10"},
        ],
    }])
    assert normalized[0]["cname_targets"] == ["api.clickaine.com"]
    events = normalize_dns_batch("adguard", "adguard-home", normalized)
    assert events[0].payload["classification"]["source"] == "adguard_cname_trackers"


def test_adguard_initial_bootstrap_handles_short_provider_retention(monkeypatch) -> None:
    import json

    from openshield.privacy import providers

    integration = Integration(
        integration_id="adguard-home", kind="adguard", display_name="AdGuard",
        capabilities=[], config={"base_url": "http://192.0.2.54"},
    )

    class FakeResponse:
        def __init__(self, payload):
            self.payload = json.dumps(payload).encode()

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, size):
            return self.payload

    # Keep the 24-hour bootstrap watermark deterministic. These records are
    # just inside the provider's retention window and therefore require the
    # follow-up page even when the CI job runs much later.
    fixed_now = datetime.fromisoformat("2026-11-14T12:00:30+00:00").timestamp()
    monkeypatch.setattr(providers.time, "time", lambda: fixed_now)

    responses = [
        {"oldest": "2026-11-13T12:01:00Z", "data": [
            {"question": {"host": "recent.example"}, "time": "2026-11-13T12:02:00Z"},
        ]},
        {"oldest": "", "data": []},
    ]
    monkeypatch.setattr(providers, "urlopen", lambda request, timeout: FakeResponse(responses.pop(0)))
    _, cursor, done = providers.fetch_dns_records_page(integration)
    assert not done
    _, final_cursor, done = providers.fetch_dns_records_page(integration, cursor)
    assert done
    assert final_cursor["complete"] is True


def test_dns_polling_lifespan_starts_and_stops_worker(monkeypatch) -> None:
    import asyncio

    from openshield.api import main

    monkeypatch.setenv("OPENSHIELD_DNS_POLL_INTERVAL_SECONDS", "60")
    stopped = asyncio.Event()

    async def fake_worker(registry, store, metrics, interval):
        assert interval == 60
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()

    monkeypatch.setattr(main, "run_dns_polling_loop", fake_worker)

    async def fake_expiration_worker(store, registry, interval_seconds=15):
        await asyncio.Event().wait()

    monkeypatch.setattr(main, "run_expiration_loop", fake_expiration_worker)

    async def exercise_lifespan():
        async with main._dns_polling_lifespan(main.app):
            await asyncio.sleep(0)

    asyncio.run(exercise_lifespan())
    assert stopped.is_set()


def test_dns_polling_retries_provider_after_transient_failure(monkeypatch) -> None:
    from openshield.api import main
    from openshield.privacy import polling
    from openshield.privacy.providers import DnsProviderError

    register_dns()
    attempts = []

    def fake_fetch_page(integration, cursor):
        attempts.append(integration.integration_id)
        if len(attempts) == 1:
            raise DnsProviderError("temporary provider outage")
        return [], {"watermark": 1, "complete": True}, True

    monkeypatch.setattr(polling, "fetch_dns_records_page", fake_fetch_page)

    from openshield.core.metrics import MetricsRegistry

    first = polling.poll_dns_sources_once(main.registry, main.store, MetricsRegistry())
    second = polling.poll_dns_sources_once(main.registry, main.store, MetricsRegistry())
    assert first[0]["status"] == "error"
    assert second[0]["status"] == "ok"
    assert attempts == ["pihole-home", "pihole-home"]


def test_dns_polling_is_idempotent_across_pages_and_overlapping_cycles(monkeypatch) -> None:
    from openshield.api import main
    from openshield.privacy import polling

    register_dns()
    records = [
        {"domain": f"query-{index}.example.net", "client": "192.168.1.30",
         "timestamp": f"2026-11-13T12:00:0{index}+00:00", "status": "allowed"}
        for index in range(3)
    ]

    def fake_fetch_page(integration, cursor):
        if not cursor:
            return records[:2], {"page": 1}, False
        if cursor.get("page") == 1:
            return records[2:], {"complete": True}, True
        return records[2:], {"complete": True}, True

    monkeypatch.setattr(polling, "fetch_dns_records_page", fake_fetch_page)

    class Metrics:
        def __init__(self):
            self.count = 0

        def increment(self, name, labels=None):
            if name == "openshield_events_ingested_total":
                self.count += 1

    metrics = Metrics()
    first = polling.poll_dns_sources_once(main.registry, main.store, metrics)
    second = polling.poll_dns_sources_once(main.registry, main.store, metrics)
    third = polling.poll_dns_sources_once(main.registry, main.store, metrics)
    assert first[0]["accepted"] == 2
    assert first[0]["pages"] == 1 and first[0]["complete"] is False
    assert second[0]["accepted"] == 1
    assert second[0]["pages"] == 1 and second[0]["complete"] is True
    assert third[0]["accepted"] == 0
    assert third[0]["duplicates"] == 1
    assert metrics.count == 3
    events = client.get("/api/v1/events?event_type=privacy.dns.query").json()["items"]
    assert {event["payload"]["domain"] for event in events} == {
        "query-0.example.net", "query-1.example.net", "query-2.example.net",
    }


def test_pihole_future_watermark_is_clamped_for_clock_skew(monkeypatch) -> None:
    from openshield.privacy import providers

    integration = Integration(
        integration_id="pihole-home", kind="pihole", display_name="Pi-hole",
        capabilities=[], config={"base_url": "http://192.0.2.53"},
    )
    requests = []

    def fake_request(base_url, path, integration=None):
        requests.append(path)
        return {"queries": []}

    monkeypatch.setattr(providers.time, "time", lambda: 1000.0)
    monkeypatch.setattr(providers, "_pihole_request", fake_request)
    _, cursor, done = providers.fetch_dns_records_page(integration, {"watermark": 5000})
    assert done
    assert "from=999" in requests[0]
    assert "until=1000" in requests[0]
    assert cursor["watermark"] == 1000.0


def test_adguard_future_watermark_is_clamped_for_clock_skew(monkeypatch) -> None:
    import json

    from openshield.privacy import providers

    integration = Integration(
        integration_id="adguard-home", kind="adguard", display_name="AdGuard",
        capabilities=[], config={"base_url": "http://192.0.2.54"},
    )

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, size):
            return json.dumps({
                "oldest": "1970-01-01T00:16:39Z",
                "data": [{"question": {"host": "recent.example"}, "time": "1970-01-01T00:16:40Z"}],
            }).encode()

    monkeypatch.setattr(providers.time, "time", lambda: 1000.0)
    monkeypatch.setattr(providers, "urlopen", lambda request, timeout: FakeResponse())
    _, cursor, done = providers.fetch_dns_records_page(integration, {"complete": True, "watermark": 5000})
    assert done
    assert cursor["watermark"] == 1000.0


def test_dns_provider_auth_failures_are_sanitized(monkeypatch) -> None:
    from urllib.error import HTTPError

    from openshield.privacy import providers
    from openshield.privacy.providers import DnsProviderError

    integration_pihole = Integration(
        integration_id="pihole-home", kind="pihole", display_name="Pi-hole",
        capabilities=[], config={"base_url": "http://192.0.2.53"},
    )
    integration_adguard = Integration(
        integration_id="adguard-home", kind="adguard", display_name="AdGuard",
        capabilities=[], config={"base_url": "http://192.0.2.54"},
    )
    monkeypatch.setenv("OPENSHIELD_PIHOLE_PASSWORD", "pihole-private-password")
    monkeypatch.setenv("OPENSHIELD_ADGUARD_USERNAME", "admin")
    monkeypatch.setenv("OPENSHIELD_ADGUARD_PASSWORD", "adguard-private-password")

    def unauthorized(request, timeout):
        raise HTTPError(request.full_url, 401, "Unauthorized", {}, None)

    monkeypatch.setattr(providers, "urlopen", unauthorized)
    for integration in (integration_pihole, integration_adguard):
        try:
            providers.fetch_dns_records(integration)
        except DnsProviderError as exc:
            assert "private-password" not in str(exc)
            assert "Unauthorized" not in str(exc)
        else:
            raise AssertionError("Provider authentication failure must be reported")


def test_dns_provider_uses_integration_ca_bundle_without_disabling_verification(monkeypatch, tmp_path) -> None:
    from openshield.privacy import providers

    class FakeSSLContext:
        def __init__(self):
            self.loaded_ca = None

        def load_verify_locations(self, *, cafile):
            self.loaded_ca = cafile

    class FakeResponse:
        def __init__(self, payload):
            self.payload = payload

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, size):
            return self.payload

    ca_dir = tmp_path / "ca"
    ca_dir.mkdir()
    monkeypatch.setenv("OPENSHIELD_CA_BUNDLE_DIR", str(ca_dir))
    monkeypatch.delenv("OPENSHIELD_PIHOLE_PASSWORD", raising=False)
    monkeypatch.delenv("OPENSHIELD_ADGUARD_USERNAME", raising=False)
    monkeypatch.delenv("OPENSHIELD_ADGUARD_PASSWORD", raising=False)

    for kind, base_url, payload in (
        ("pihole", "https://pihole.example", b'{"queries":[]}'),
        ("adguard", "https://adguard.example", b'{"data":[]}'),
    ):
        context = FakeSSLContext()
        seen = {}

        monkeypatch.setattr(
            providers.ssl, "create_default_context",
            lambda expected_context=context: expected_context,
        )

        def make_urlopen(expected_payload, captured):
            def fake_urlopen(request, timeout, **kwargs):
                captured["request"] = request
                captured["context"] = kwargs.get("context")
                return FakeResponse(expected_payload)
            return fake_urlopen

        monkeypatch.setattr(providers, "urlopen", make_urlopen(payload, seen))
        ca_file = ca_dir / f"{kind}.pem"
        ca_file.write_text("test CA bundle")
        integration = Integration(
            integration_id=f"{kind}-tls", kind=kind, display_name=kind.title(),
            capabilities=[], config={
                "base_url": base_url,
                "ca_bundle_path": str(ca_file),
            },
        )

        assert fetch_dns_records(integration) == []
        assert seen["context"] is context
        assert context.loaded_ca == str(ca_file.resolve())
        assert seen["request"].full_url.startswith("https://")


def test_dns_provider_rejects_ca_bundle_for_http_and_relative_paths(monkeypatch, tmp_path) -> None:
    ca_dir = tmp_path / "ca"
    ca_dir.mkdir()
    ca_file = ca_dir / "root.pem"
    ca_file.write_text("test CA bundle")
    monkeypatch.setenv("OPENSHIELD_CA_BUNDLE_DIR", str(ca_dir))
    from openshield.privacy.providers import DnsProviderError, _ssl_context

    http_integration = Integration(
        integration_id="pihole-http", kind="pihole", display_name="Pi-hole",
        capabilities=[], config={
            "base_url": "http://192.0.2.53",
            "ca_bundle_path": str(ca_file),
        },
    )
    relative_integration = Integration(
        integration_id="pihole-relative", kind="pihole", display_name="Pi-hole",
        capabilities=[], config={
            "base_url": "https://pihole.example",
            "ca_bundle_path": "certs/root.pem",
        },
    )

    for integration, url in (
        (http_integration, "http://192.0.2.53/api/queries"),
        (relative_integration, "https://pihole.example/api/queries"),
    ):
        try:
            _ssl_context(integration, url)
        except DnsProviderError:
            pass
        else:
            raise AssertionError("Invalid custom CA configuration must be rejected")


def test_dns_integration_validates_custom_ca_bundle_path(monkeypatch, tmp_path) -> None:
    ca_dir = tmp_path / "ca"
    ca_dir.mkdir()
    ca_file = ca_dir / "root.pem"
    ca_file.write_text("test CA bundle")
    monkeypatch.setenv("OPENSHIELD_CA_BUNDLE_DIR", str(ca_dir))
    invalid = client.post("/api/v1/integrations", json={
        "integration_id": "pihole-relative-ca",
        "kind": "pihole",
        "display_name": "Pi-hole",
        "config": {
            "base_url": "https://pihole.example",
            "ca_bundle_path": "certs/root.pem",
        },
    })
    assert invalid.status_code == 422

    valid = client.post("/api/v1/integrations", json={
        "integration_id": "pihole-custom-ca",
        "kind": "pihole",
        "display_name": "Pi-hole",
        "config": {
            "base_url": "https://pihole.example",
            "ca_bundle_path": str(ca_file),
        },
    })
    assert valid.status_code == 201


def test_dns_provider_credentials_are_encrypted_per_integration_and_never_returned(monkeypatch) -> None:
    from cryptography.fernet import Fernet

    from openshield.api import main
    from openshield.core.secrets import SecretStore

    monkeypatch.setenv("OPENSHIELD_SECRET_KEY", Fernet.generate_key().decode())
    register_dns("pihole-a", "pihole")
    register_dns("pihole-b", "pihole")
    register_dns("adguard-a", "adguard")
    first = client.put("/api/v1/integrations/pihole-a/dns-provider-credentials", json={"password": "pihole-password-a"})
    second = client.put("/api/v1/integrations/pihole-b/dns-provider-credentials", json={"password": "pihole-password-b"})
    adguard = client.put("/api/v1/integrations/adguard-a/dns-provider-credentials", json={"username": "adguard-user", "password": "adguard-password"})
    assert first.status_code == second.status_code == adguard.status_code == 200
    assert "pihole-password" not in first.text and "adguard-password" not in adguard.text
    assert SecretStore(main.store).get("pihole-a") == {"password": "pihole-password-a"}
    assert SecretStore(main.store).get("pihole-b") == {"password": "pihole-password-b"}
    assert SecretStore(main.store).get("adguard-a") == {"username": "adguard-user", "password": "adguard-password"}
    encrypted = main.store.get_integration_secret("pihole-a")
    assert encrypted and b"pihole-password-a" not in encrypted
    assert "pihole-password-a" not in client.get("/api/v1/integrations").text
    assert client.delete("/api/v1/integrations/pihole-a/dns-provider-credentials").status_code == 204
    assert SecretStore(main.store).get("pihole-a") is None


def test_resilient_dns_normalization_isolates_bad_records() -> None:
    from openshield.privacy.dns import normalize_dns_batch_resilient

    events, rejected = normalize_dns_batch_resilient("pihole", "pihole-home", [
        {"domain": "valid.example", "timestamp": "2026-11-15T12:00:00Z"},
        {"domain": "invalid domain", "timestamp": "2026-11-15T12:00:01Z"},
        {"domain": "bad-time.example", "timestamp": "not-a-timestamp"},
        {"domain": "empty-time.example", "timestamp": ""},
        None,
    ])

    assert len(events) == 1
    assert events[0].payload["domain"] == "valid.example"
    assert rejected == [
        {"record_index": 1, "reason": "invalid_domain"},
        {"record_index": 2, "reason": "invalid_timestamp"},
        {"record_index": 3, "reason": "invalid_timestamp"},
        {"record_index": 4, "reason": "invalid_record_shape"},
    ]
    assert all("domain" not in item and "value" not in item for item in rejected)


def test_dns_polling_ingests_499_of_500_records_and_resumes_next_page_next_cycle(
    monkeypatch,
) -> None:
    from openshield.api import main
    from openshield.privacy import polling

    register_dns()
    valid_records = [
        {
            "domain": f"host-{index}.example",
            "timestamp": datetime(2026, 11, 15, 12, 0, index % 60, tzinfo=UTC).isoformat(),
            "status": "allowed",
        }
        for index in range(499)
    ]
    records = valid_records + [{
        "domain": "invalid domain",
        "timestamp": datetime(2026, 11, 15, 12, 1, tzinfo=UTC).isoformat(),
    }]
    fetch_cursors = []

    def fake_fetch_page(integration, cursor):
        fetch_cursors.append(cursor)
        if cursor is None:
            return records, {"offset": 500, "complete": False}, False
        assert cursor == {"offset": 500, "complete": False}
        return [{
            "domain": "next-page.example",
            "timestamp": datetime(2026, 11, 15, 12, 2, tzinfo=UTC).isoformat(),
        }], {"offset": 501, "complete": True}, True

    monkeypatch.setattr(polling, "fetch_dns_records_page", fake_fetch_page)

    class Metrics:
        def __init__(self):
            self.counts = {}
            self.samples = []

        def increment(self, name, labels=None):
            self.counts[name] = self.counts.get(name, 0) + 1
            self.samples.append((name, labels or {}))

    metrics = Metrics()
    first = polling.poll_dns_sources_once(main.registry, main.store, metrics)
    assert first == [{
        "integration_id": "pihole-home", "status": "ok", "received": 500,
        "accepted": 499, "duplicates": 0, "rejected": 1, "pages": 1,
        "complete": False,
    }]
    assert main.store.get_integration_poll_cursor("pihole-home") == {
        "offset": 500, "complete": False,
    }
    assert metrics.counts["openshield_events_ingested_total"] == 499
    assert metrics.counts["openshield_dns_records_rejected_total"] == 1
    assert (
        "openshield_dns_poll_records_total",
        {"provider": "pihole", "outcome": "rejected"},
    ) in metrics.samples
    events = client.get("/api/v1/events?event_type=privacy.dns.query&limit=500").json()["items"]
    assert len(events) == 499
    rejection_audit = next(
        item for item in client.get("/api/v1/audit").json()
        if item["action"] == "privacy.provider_poll.records_rejected"
    )
    assert rejection_audit["details"]["count"] == 1
    assert rejection_audit["details"]["reasons"] == {"invalid_domain": 1}
    assert "invalid domain" not in str(rejection_audit["details"])

    second = polling.poll_dns_sources_once(main.registry, main.store, metrics)
    assert fetch_cursors[1] == {"offset": 500, "complete": False}
    assert second[0]["received"] == second[0]["accepted"] == 1
    assert second[0]["rejected"] == 0
    assert main.store.get_integration_poll_cursor("pihole-home") == {
        "offset": 501, "complete": True,
    }
    assert len(client.get("/api/v1/events?event_type=privacy.dns.query&limit=500").json()["items"]) == 500


def test_dns_polling_isolates_normalization_failure_and_continues(monkeypatch) -> None:
    from openshield.api import main
    from openshield.core.metrics import MetricsRegistry
    from openshield.privacy import polling

    register_dns("a-pihole-home", "pihole")
    register_dns("b-adguard-home", "adguard")
    integrations = sorted(main.registry.list_all(), key=lambda item: item.integration_id)
    monkeypatch.setattr(main.registry, "list_all", lambda: integrations)
    calls = []
    original_normalize = polling.normalize_dns_batch_resilient

    def fake_fetch_page(integration, cursor):
        calls.append(integration.integration_id)
        return [{
            "domain": f"{integration.integration_id}.example",
            "timestamp": "2026-11-15T12:00:00Z",
        }], {"offset": 1, "complete": True}, True

    def fail_first_normalization(kind, integration_id, records, overrides):
        if integration_id == "a-pihole-home":
            raise ValueError("malformed provider page")
        return original_normalize(kind, integration_id, records, overrides)

    monkeypatch.setattr(polling, "fetch_dns_records_page", fake_fetch_page)
    monkeypatch.setattr(polling, "normalize_dns_batch_resilient", fail_first_normalization)
    metrics = MetricsRegistry()

    outcomes = polling.poll_dns_sources_once(main.registry, main.store, metrics)

    assert calls == ["a-pihole-home", "b-adguard-home"]
    assert outcomes[0] == {
        "integration_id": "a-pihole-home",
        "status": "error",
        "category": "normalization_error",
    }
    assert outcomes[1]["status"] == "ok"
    assert main.store.get_integration_poll_cursor("a-pihole-home") is None
    assert main.store.get_integration_poll_cursor("b-adguard-home") == {
        "offset": 1, "complete": True,
    }
    source = next(
        item for item in client.get("/api/v1/privacy/sources").json()
        if item["integration_id"] == "a-pihole-home"
    )
    assert source["last_error_category"] == "normalization_error"
    assert source["retryable"] is False
    assert 'category="normalization_error",provider="pihole"' in metrics.render()


def test_dns_polling_isolates_unexpected_provider_error(monkeypatch, caplog) -> None:
    from openshield.api import main
    from openshield.core.metrics import MetricsRegistry
    from openshield.privacy import polling

    register_dns("a-pihole-home", "pihole")
    register_dns("b-adguard-home", "adguard")
    integrations = sorted(main.registry.list_all(), key=lambda item: item.integration_id)
    monkeypatch.setattr(main.registry, "list_all", lambda: integrations)
    calls = []

    def fake_fetch_page(integration, cursor):
        calls.append(integration.integration_id)
        if integration.integration_id == "a-pihole-home":
            raise RuntimeError("secret provider payload must not be logged")
        return [], {"offset": 1, "complete": True}, True

    monkeypatch.setattr(polling, "fetch_dns_records_page", fake_fetch_page)
    metrics = MetricsRegistry()
    outcomes = polling.poll_dns_sources_once(main.registry, main.store, metrics)

    assert calls == ["a-pihole-home", "b-adguard-home"]
    assert outcomes[0]["category"] == "unexpected_error"
    assert outcomes[1]["status"] == "ok"
    assert main.store.get_integration_poll_cursor("a-pihole-home") is None
    assert main.store.get_integration_poll_cursor("b-adguard-home") == {
        "offset": 1, "complete": True,
    }
    assert "secret provider payload" not in caplog.text
    source = next(
        item for item in client.get("/api/v1/privacy/sources").json()
        if item["integration_id"] == "a-pihole-home"
    )
    assert source["last_error_category"] == "unexpected_error"


def test_dns_database_failure_aborts_cycle_and_replays_without_cursor_loss(
    monkeypatch,
) -> None:
    import psycopg

    from openshield.api import main
    from openshield.core.metrics import MetricsRegistry
    from openshield.privacy import polling

    register_dns("a-pihole-home", "pihole")
    register_dns("b-adguard-home", "adguard")
    integrations = sorted(main.registry.list_all(), key=lambda item: item.integration_id)
    monkeypatch.setattr(main.registry, "list_all", lambda: integrations)
    calls = []

    def fake_fetch_page(integration, cursor):
        calls.append(integration.integration_id)
        if integration.integration_id == "a-pihole-home":
            return [{
                "domain": "durable.example",
                "timestamp": "2026-11-15T12:00:00Z",
            }], {"offset": 1, "complete": True}, True
        return [], {"offset": 2, "complete": True}, True

    monkeypatch.setattr(polling, "fetch_dns_records_page", fake_fetch_page)
    original_insert_audit = main.store._insert_audit
    audit_calls = 0

    def fail_checkpoint_audit(cursor, action, actor_id, target_id, details):
        nonlocal audit_calls
        audit_calls += 1
        if audit_calls == 2:
            raise psycopg.OperationalError("simulated database outage")
        original_insert_audit(cursor, action, actor_id, target_id, details)

    monkeypatch.setattr(main.store, "_insert_audit", fail_checkpoint_audit)
    metrics = MetricsRegistry()

    with pytest.raises(polling.PollingDatabaseError):
        polling.poll_dns_sources_once(main.registry, main.store, metrics)

    assert calls == ["a-pihole-home"]
    assert main.store.get_integration_poll_cursor("a-pihole-home") is None
    assert main.store.get_integration_poll_cursor("b-adguard-home") is None
    assert len(client.get("/api/v1/events?event_type=privacy.dns.query").json()["items"]) == 1
    assert not any(
        item["action"] == "privacy.provider_poll.completed"
        and item["target_id"] == "a-pihole-home"
        for item in client.get("/api/v1/audit").json()
    )
    source = next(
        item for item in client.get("/api/v1/privacy/sources").json()
        if item["integration_id"] == "a-pihole-home"
    )
    assert source["last_error_category"] == "database_error"
    assert source["retryable"] is True
    assert 'category="database_error",provider="pihole"' in metrics.render()

    monkeypatch.setattr(main.store, "_insert_audit", original_insert_audit)
    retry = polling.poll_dns_sources_once(main.registry, main.store, metrics)
    assert calls == ["a-pihole-home", "a-pihole-home", "b-adguard-home"]
    assert retry[0]["accepted"] == 0
    assert retry[0]["duplicates"] == 1
    assert main.store.get_integration_poll_cursor("a-pihole-home") == {
        "offset": 1, "complete": True,
    }
    assert retry[1]["status"] == "ok"
    assert len(client.get("/api/v1/events?event_type=privacy.dns.query").json()["items"]) == 1

 
 
def test_cname_tracker_classification_uses_label_suffix_membership(monkeypatch) -> None:
    from openshield.privacy import dns

    class MembershipOnlySet(set):
        def __iter__(self):
            raise AssertionError("classification must not scan the tracker feed")

    monkeypatch.setattr(dns, "CNAME_TRACKERS", MembershipOnlySet({"tracker.example"}))

    exact = dns.classify_domain_metadata(
        "site.example", cname_targets=["tracker.example"],
    )
    nested = dns.classify_domain_metadata(
        "site.example", cname_targets=["edge.eu.tracker.example"],
    )
    unrelated = dns.classify_domain_metadata(
        "site.example", cname_targets=["nottracker.example"],
    )

    assert exact["category"] == nested["category"] == "tracker"
    assert unrelated["category"] == "unclassified"



def test_adguard_idle_page_filters_records_at_or_before_watermark(monkeypatch) -> None:
    import json

    from openshield.privacy import providers

    integration = Integration(
        integration_id="adguard-home", kind="adguard", display_name="AdGuard",
        capabilities=[], config={"base_url": "http://192.0.2.54"},
    )
    watermark = datetime.fromisoformat("2026-11-13T12:00:00+00:00").timestamp()
    payload = {
        "oldest": "2026-11-13T11:59:40Z",
        "data": [
            {"question": {"host": "old-one.example"}, "time": "2026-11-13T11:59:50Z"},
            {"question": {"host": "old-two.example"}, "time": "2026-11-13T11:59:40Z"},
        ],
    }

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self, _size):
            return json.dumps(payload).encode()

    monkeypatch.setattr(providers, "urlopen", lambda *_args, **_kwargs: FakeResponse())
    records, next_cursor, done = providers.fetch_dns_records_page(
        integration, {"watermark": watermark, "complete": True},
    )

    assert records == []
    assert done is True
    assert next_cursor == {"watermark": watermark, "complete": True}


def test_adguard_watermark_keeps_new_equal_and_slightly_late_records(monkeypatch) -> None:
    import json

    from openshield.privacy import providers

    integration = Integration(
        integration_id="adguard-home", kind="adguard", display_name="AdGuard",
        capabilities=[], config={"base_url": "http://192.0.2.54"},
    )
    watermark = datetime.fromisoformat("2026-11-13T12:00:00+00:00").timestamp()
    payload = {
        "oldest": "2026-11-13T11:59:58Z",
        "data": [
            {"question": {"host": "new.example"}, "time": "2026-11-13T12:00:02Z"},
            {"question": {"host": "same-second.example"}, "time": "2026-11-13T12:00:00Z"},
            {"question": {"host": "late.example"}, "time": "2026-11-13T11:59:59.500Z"},
            {"question": {"host": "too-old.example"}, "time": "2026-11-13T11:59:58Z"},
        ],
    }

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self, _size):
            return json.dumps(payload).encode()

    monkeypatch.setattr(providers, "urlopen", lambda *_args, **_kwargs: FakeResponse())
    records, next_cursor, done = providers.fetch_dns_records_page(
        integration, {"watermark": watermark, "complete": True},
    )

    assert [item["domain"] for item in records] == [
        "new.example", "same-second.example", "late.example",
    ]
    assert done is True
    assert next_cursor["watermark"] == datetime.fromisoformat(
        "2026-11-13T12:00:02+00:00"
    ).timestamp()
    assert next_cursor["watermark"] >= watermark
