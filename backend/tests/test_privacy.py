from datetime import UTC, datetime

from fastapi.testclient import TestClient

from openshield.api.main import app
from openshield.privacy.dns import classify_domain, normalize_domain, normalize_dns_batch

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
    stored = client.get("/api/v1/events?event_type=privacy.dns.query").json()
    assert len(stored) == 1
    assert stored[0]["payload"]["category"] == "tracker"
    assert stored[0]["payload"]["status"] == "blocked"
    assert "password" not in stored[0]["payload"]


def test_adguard_dns_ingestion_and_provider_probe() -> None:
    register_dns("adguard-home", "adguard")
    probe = client.get("/api/v1/integrations/adguard-home/probe")
    assert probe.status_code == 200
    assert probe.json()["kind"] == "adguard"
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
    source = client.get("/api/v1/privacy/sources").json()[0]
    assert source["status"] == "healthy"
    assert source["queries_seen"] == 1
