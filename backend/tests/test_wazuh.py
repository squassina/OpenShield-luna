import base64
from unittest.mock import Mock, patch

import pytest

from openshield.integrations.wazuh import WazuhClient, WazuhError


def response(payload: bytes):
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, size):
            assert size == WazuhClient.MAX_RESPONSE_BYTES + 1
            return payload

    return FakeResponse()


def test_wazuh_authenticates_and_reads_only_manager_and_agent_endpoints():
    client = WazuhClient("https://wazuh.example:55000", "reader", "strong-password")
    opener = Mock()
    opener.open.side_effect = [
        response(b"jwt-session-token"),
        response(b'{"data":{"api_version":"4.14.0"},"error":0}'),
        response(b'{"data":{"affected_items":[{"version":"4.14.0"}]},"error":0}'),
        response(b'{"data":{"affected_items":[{"wazuh-analysisd":"running"}]},"error":0}'),
        response(
            b'{"data":{"affected_items":[{"id":"001","status":"active"}],'
            b'"total_affected_items":1},"error":0}'
        ),
    ]
    with patch("openshield.integrations.wazuh.build_opener", return_value=opener):
        result = client.diagnostics()

    requests = [call.args[0] for call in opener.open.call_args_list]
    assert [request.get_method() for request in requests] == [
        "POST", "GET", "GET", "GET", "GET"
    ]
    assert requests[0].full_url.endswith("/security/user/authenticate?raw=true")
    basic = requests[0].get_header("Authorization")
    assert base64.b64decode(basic.removeprefix("Basic ")).decode() == "reader:strong-password"
    assert all(
        request.get_header("Authorization") == "Bearer jwt-session-token"
        for request in requests[1:]
    )
    assert requests[1].full_url.endswith("/")
    assert requests[2].full_url.endswith("/manager/info")
    assert requests[3].full_url.endswith("/manager/status")
    assert requests[4].full_url.endswith(
        "/agents?limit=500&select=id,name,status,ip,version"
    )
    assert result["summary"] == {
        "agents_available": 1,
        "agents_returned": 1,
        "agents_limit": 500,
    }


@pytest.mark.parametrize(
    "url",
    [
        "",
        "ftp://wazuh.example",
        "https://user:pass@wazuh.example",
        "https://wazuh.example/path",
        "https://wazuh.example/?token=x",
        "https://wazuh.example/#fragment",
    ],
)
def test_wazuh_rejects_invalid_base_url(url):
    with pytest.raises(ValueError):
        WazuhClient(url, "reader", "strong-password")


def test_wazuh_rejects_invalid_credentials_and_timeout():
    for username, password in (
        ("", "strong-password"),
        ("reader:admin", "strong-password"),
        ("reader\r\nX-Test: yes", "strong-password"),
        ("reader", ""),
        ("reader", "bad\npassword"),
    ):
        with pytest.raises(ValueError):
            WazuhClient("https://wazuh.example:55000", username, password)
    with pytest.raises(ValueError, match="timeout"):
        WazuhClient("https://wazuh.example:55000", "reader", "strong-password", 31)


def test_wazuh_rejects_unsupported_operations():
    client = WazuhClient("https://wazuh.example:55000", "reader", "strong-password")
    with pytest.raises(ValueError, match="Unsupported"):
        client._request("/agents", "DELETE", {})
    with pytest.raises(ValueError, match="Unsupported"):
        client._request("/manager/restart", "PUT", {})


def test_wazuh_rejects_missing_authentication_token():
    client = WazuhClient("https://wazuh.example:55000", "reader", "strong-password")
    opener = Mock()
    opener.open.return_value = response(b"")
    with (
        patch("openshield.integrations.wazuh.build_opener", return_value=opener),
        pytest.raises(WazuhError, match="no usable token"),
    ):
        client._login()


def test_wazuh_rejects_invalid_json_and_oversized_responses():
    client = WazuhClient("https://wazuh.example:55000", "reader", "strong-password")
    opener = Mock()
    opener.open.return_value = response(b"not-json")
    with (
        patch("openshield.integrations.wazuh.build_opener", return_value=opener),
        pytest.raises(WazuhError, match="invalid JSON"),
    ):
        client._get("/", "token")

    opener.open.return_value = response(b"x" * (WazuhClient.MAX_RESPONSE_BYTES + 1))
    with (
        patch("openshield.integrations.wazuh.build_opener", return_value=opener),
        pytest.raises(WazuhError, match="size limit"),
    ):
        client._get("/", "token")


def test_wazuh_rejects_api_application_errors_and_invalid_agent_envelope():
    client = WazuhClient("https://wazuh.example:55000", "reader", "strong-password")
    opener = Mock()
    opener.open.return_value = response(b'{"error": 3000, "message": "forbidden"}')
    with (
        patch("openshield.integrations.wazuh.build_opener", return_value=opener),
        pytest.raises(WazuhError, match="application error"),
    ):
        client._get("/", "token")

    opener.open.side_effect = [
        response(b"jwt-session-token"),
        response(b'{"data":{},"error":0}'),
        response(b'{"data":{},"error":0}'),
        response(b'{"data":{},"error":0}'),
        response(b'{"data":{"total_affected_items":0},"error":0}'),
    ]
    with (
        patch("openshield.integrations.wazuh.build_opener", return_value=opener),
        pytest.raises(WazuhError, match="unexpected response"),
    ):
        client.diagnostics()
