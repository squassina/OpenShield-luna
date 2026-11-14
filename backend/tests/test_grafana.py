from unittest.mock import Mock, patch
from urllib.error import HTTPError

import pytest

from openshield.integrations.grafana import GrafanaClient, GrafanaError


def response(payload: bytes):
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, size):
            assert size == GrafanaClient.MAX_RESPONSE_BYTES + 1
            return payload

    return FakeResponse()


def test_grafana_reads_health_and_dashboard_metadata_with_bearer_auth():
    client = GrafanaClient("https://grafana.example:3000", "read-token")
    opener = Mock()
    opener.open.side_effect = [
        response(b'{"database":"ok","version":"11.2.0","commit":"abc123"}'),
        response(
            b'[{"uid":"abc","title":"Overview","type":"dash-db","url":"/d/abc/overview",'
            b'"folderTitle":"Home","tags":["infra"]}]'
        ),
    ]
    with patch("openshield.integrations.grafana.build_opener", return_value=opener):
        result = client.diagnostics()
    requests = [call.args[0] for call in opener.open.call_args_list]
    assert [request.get_method() for request in requests] == ["GET", "GET"]
    assert requests[0].full_url.endswith("/api/health")
    assert requests[1].full_url.endswith("/api/search/?type=dash-db&limit=100")
    assert all(request.get_header("Authorization") == "Bearer read-token" for request in requests)
    assert result["health"]["database"] == "ok"
    assert result["summary"] == {"dashboards_returned": 1, "dashboards_limit": 100}
    assert result["dashboards"][0]["uid"] == "abc"


def test_grafana_supports_unauthenticated_read_only_api():
    client = GrafanaClient("http://grafana.example:3000")
    opener = Mock()
    opener.open.return_value = response(b'{"database":"ok","version":"11.2.0"}')
    with patch("openshield.integrations.grafana.build_opener", return_value=opener):
        client._get("/api/health")
    assert opener.open.call_args.args[0].get_header("Authorization") is None


@pytest.mark.parametrize("url", [
    "",
    "ftp://grafana.example",
    "https://user:pass@grafana.example",
    "https://grafana.example/path",
    "https://grafana.example/?token=x",
])
def test_grafana_rejects_invalid_base_url(url):
    with pytest.raises(ValueError):
        GrafanaClient(url)


def test_grafana_rejects_invalid_token_timeout_and_mutation_paths():
    with pytest.raises(ValueError):
        GrafanaClient("https://grafana.example", "bad\ntoken")
    with pytest.raises(ValueError, match="timeout"):
        GrafanaClient("https://grafana.example", timeout=31)
    with pytest.raises(ValueError, match="Unsupported"):
        GrafanaClient("https://grafana.example")._get("/api/dashboards/db")


def test_grafana_rejects_invalid_json_and_oversized_responses():
    client = GrafanaClient("https://grafana.example")
    opener = Mock()
    opener.open.return_value = response(b"not-json")
    with patch("openshield.integrations.grafana.build_opener", return_value=opener), pytest.raises(
        GrafanaError, match="invalid JSON"
    ):
        client._get("/api/health")
    opener.open.return_value = response(b"x" * (GrafanaClient.MAX_RESPONSE_BYTES + 1))
    with patch("openshield.integrations.grafana.build_opener", return_value=opener), pytest.raises(
        GrafanaError, match="size limit"
    ):
        client._get("/api/health")


def test_grafana_rejects_unexpected_health_and_search_envelopes():
    client = GrafanaClient("https://grafana.example")
    opener = Mock()
    opener.open.side_effect = [
        response(b'{"database":"ok"}'),
        response(b"[]"),
    ]
    with patch("openshield.integrations.grafana.build_opener", return_value=opener), pytest.raises(
        GrafanaError, match="health endpoint"
    ):
        client.diagnostics()

    opener.open.side_effect = [
        response(b'{"database":"ok","version":"11.2.0"}'),
        response(b'{"items":[]}'),
    ]
    with patch("openshield.integrations.grafana.build_opener", return_value=opener), pytest.raises(
        GrafanaError, match="search endpoint"
    ):
        client.diagnostics()


@pytest.mark.parametrize(
    ("status", "message"),
    [(302, "HTTP 302"), (401, "rejected the configured credentials")],
)
def test_grafana_rejects_redirects_and_authentication_failures(status, message):
    client = GrafanaClient("https://grafana.example", "read-token")
    opener = Mock()
    opener.open.side_effect = HTTPError(
        "https://grafana.example/api/health", status, "request failed", {}, None
    )
    with patch("openshield.integrations.grafana.build_opener", return_value=opener), pytest.raises(
        GrafanaError, match=message
    ):
        client._get("/api/health")
