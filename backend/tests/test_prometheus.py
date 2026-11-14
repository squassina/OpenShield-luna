from unittest.mock import Mock, patch

import pytest

from openshield.integrations.prometheus import PrometheusClient, PrometheusError


def response(payload: bytes):
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, size):
            assert size == PrometheusClient.MAX_RESPONSE_BYTES + 1
            return payload

    return FakeResponse()


def test_prometheus_reads_runtime_and_targets_with_optional_bearer_auth():
    client = PrometheusClient("https://prometheus.example:9090", "read-token")
    opener = Mock()
    opener.open.side_effect = [
        response(b'{"status":"success","data":{"version":"3.0.0"}}'),
        response(b'{"status":"success","data":{"activeTargets":[{"health":"up"},{"health":"down"}]}}'),
    ]
    with patch("openshield.integrations.prometheus.build_opener", return_value=opener):
        result = client.diagnostics()
    requests = [call.args[0] for call in opener.open.call_args_list]
    assert [request.get_method() for request in requests] == ["GET", "GET"]
    assert requests[0].full_url.endswith("/api/v1/status/runtimeinfo")
    assert requests[1].full_url.endswith("/api/v1/targets?state=active")
    assert all(request.get_header("Authorization") == "Bearer read-token" for request in requests)
    assert result["summary"] == {
        "targets_available": 2, "targets_up": 1, "targets_down": 1, "targets_limit": 100,
    }


def test_prometheus_supports_unauthenticated_read_only_api():
    client = PrometheusClient("http://prometheus.example:9090")
    opener = Mock()
    opener.open.return_value = response(b'{"status":"success","data":{"activeTargets":[]}}')
    with patch("openshield.integrations.prometheus.build_opener", return_value=opener):
        client._get("/api/v1/targets?state=active")
    assert opener.open.call_args.args[0].get_header("Authorization") is None


@pytest.mark.parametrize("url", [
    "", "ftp://prometheus.example", "https://user:pass@prometheus.example",
    "https://prometheus.example/path", "https://prometheus.example/?token=x",
])
def test_prometheus_rejects_invalid_base_url(url):
    with pytest.raises(ValueError):
        PrometheusClient(url)


def test_prometheus_rejects_invalid_token_timeout_and_mutation_paths():
    with pytest.raises(ValueError):
        PrometheusClient("https://prometheus.example", "bad\ntoken")
    with pytest.raises(ValueError, match="timeout"):
        PrometheusClient("https://prometheus.example", timeout=31)
    with pytest.raises(ValueError, match="Unsupported"):
        PrometheusClient("https://prometheus.example")._get("/api/v1/admin/tsdb/delete_series")


def test_prometheus_rejects_invalid_json_and_oversized_responses():
    client = PrometheusClient("https://prometheus.example")
    opener = Mock()
    opener.open.return_value = response(b"not-json")
    with patch("openshield.integrations.prometheus.build_opener", return_value=opener), pytest.raises(
        PrometheusError, match="invalid JSON"
    ):
        client._get("/api/v1/status/runtimeinfo")
    opener.open.return_value = response(b"x" * (PrometheusClient.MAX_RESPONSE_BYTES + 1))
    with patch("openshield.integrations.prometheus.build_opener", return_value=opener), pytest.raises(
        PrometheusError, match="size limit"
    ):
        client._get("/api/v1/status/runtimeinfo")
