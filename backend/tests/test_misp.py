import json
from unittest.mock import Mock, patch

import pytest

from openshield.integrations.misp import MispClient, MispError


def response(payload: bytes):
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, size):
            assert size == MispClient.MAX_RESPONSE_BYTES + 1
            return payload

    return FakeResponse()


def test_misp_diagnostics_reads_version_with_api_key():
    client = MispClient("https://misp.example", "api-key")
    opener = Mock()
    opener.open.return_value = response(b'{"version":"2.4.190"}')
    with patch("openshield.integrations.misp.build_opener", return_value=opener):
        assert client.diagnostics() == {"version": "2.4.190", "api": "connected"}
    request = opener.open.call_args.args[0]
    assert request.get_method() == "GET"
    assert request.get_header("Authorization") == "api-key"
    assert request.full_url == "https://misp.example/servers/getVersion"


def test_misp_search_returns_only_supported_to_ids_indicators():
    payload = {
        "response": {
            "Attribute": [
                {
                    "uuid": "indicator-1", "type": "ip-src", "value": "198.51.100.10",
                    "to_ids": True, "category": "Network activity", "event_id": "42",
                },
                {
                    "uuid": "indicator-2", "type": "domain", "value": "bad.example",
                    "to_ids": "1",
                },
                {
                    "uuid": "indicator-3", "type": "comment", "value": "not-an-ioc",
                    "to_ids": True,
                },
                {
                    "uuid": "indicator-4", "type": "ip-dst", "value": "203.0.113.9",
                    "to_ids": False,
                },
            ]
        }
    }
    client = MispClient("https://misp.example", "api-key")
    opener = Mock()
    opener.open.return_value = response(json.dumps(payload).encode())
    with patch("openshield.integrations.misp.build_opener", return_value=opener):
        result = client.search_indicators(limit=25)
    assert [item["indicator_id"] for item in result] == ["indicator-1", "indicator-2"]
    request = opener.open.call_args.args[0]
    assert request.get_method() == "POST"
    assert request.full_url.endswith("/attributes/restSearch")
    body = json.loads(request.data)
    assert body["to_ids"] is True
    assert body["limit"] == 25


@pytest.mark.parametrize(
    "url",
    ["", "ftp://host", "https://user:pass@host", "https://host/path", "https://host/?q=1"],
)
def test_misp_rejects_invalid_base_url(url):
    with pytest.raises(ValueError):
        MispClient(url, "api-key")


def test_misp_rejects_invalid_api_key_and_limits():
    with pytest.raises(ValueError, match="API key"):
        MispClient("https://misp.example", "bad\r\nX-Injected: yes")
    client = MispClient("https://misp.example", "api-key")
    with pytest.raises(ValueError, match="limit"):
        client.search_indicators(1001)


def test_misp_rejects_oversized_response():
    client = MispClient("https://misp.example", "api-key")
    opener = Mock()
    opener.open.return_value = response(b"x" * (MispClient.MAX_RESPONSE_BYTES + 1))
    with (
        patch("openshield.integrations.misp.build_opener", return_value=opener),
        pytest.raises(MispError, match="size limit"),
    ):
        client.diagnostics()


def test_misp_rejects_unexpected_search_shape():
    client = MispClient("https://misp.example", "api-key")
    opener = Mock()
    opener.open.return_value = response(b'{"response":{"items":[]}}')
    with (
        patch("openshield.integrations.misp.build_opener", return_value=opener),
        pytest.raises(MispError, match="unexpected response"),
    ):
        client.search_indicators()
