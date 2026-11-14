from unittest.mock import Mock, patch

import pytest

from openshield.integrations.pfsense import PfSenseClient, PfSenseError


def response(payload: bytes):
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, size):
            assert size == PfSenseClient.MAX_RESPONSE_BYTES + 1
            return payload

    return FakeResponse()


def test_pfsense_client_uses_api_key_and_get_only():
    client = PfSenseClient("https://firewall.example", "api-key")
    opener = Mock()
    opener.open.return_value = response(b'{"status":"ok"}')
    with patch("openshield.integrations.pfsense.build_opener", return_value=opener):
        assert client.get("/api/v2/status/system") == {"status": "ok"}
    sent = opener.open.call_args.args[0]
    assert sent.get_method() == "GET"
    assert sent.get_header("X-api-key") == "api-key"
    assert opener.open.call_args.kwargs["timeout"] == 8.0


@pytest.mark.parametrize(
    "url",
    ["", "ftp://host", "https://user:pass@host", "https://host/path", "https://host/path?q=1"],
)
def test_pfsense_rejects_invalid_base_url(url):
    with pytest.raises(ValueError):
        PfSenseClient(url, "api-key")


def test_pfsense_rejects_empty_or_header_injection_api_key():
    for key in ("", "bad\r\nX-Injected: yes"):
        with pytest.raises(ValueError):
            PfSenseClient("https://firewall.example", key)


@pytest.mark.parametrize(
    "path",
    [
        "/api/../etc/passwd",
        "/api/v2/status/system?secret=x",
        "/api/v1/status/system",
        "/api/v2//status",
    ],
)
def test_pfsense_rejects_invalid_api_path(path):
    client = PfSenseClient("https://firewall.example", "api-key")
    with pytest.raises(ValueError):
        client.get(path)


def test_pfsense_rejects_invalid_json():
    client = PfSenseClient("https://firewall.example", "api-key")
    opener = Mock()
    opener.open.return_value = response(b"not-json")
    with (
        patch("openshield.integrations.pfsense.build_opener", return_value=opener),
        pytest.raises(PfSenseError, match="invalid JSON"),
    ):
        client.get("/api/v2/status/system")


def test_pfsense_rejects_oversized_response():
    client = PfSenseClient("https://firewall.example", "api-key")
    opener = Mock()
    opener.open.return_value = response(b"x" * (PfSenseClient.MAX_RESPONSE_BYTES + 1))
    with (
        patch("openshield.integrations.pfsense.build_opener", return_value=opener),
        pytest.raises(PfSenseError, match="size limit"),
    ):
        client.get("/api/v2/status/system")


def test_pfsense_diagnostics_only_calls_read_endpoints():
    client = PfSenseClient("https://firewall.example", "api-key")
    opener = Mock()
    opener.open.side_effect = [
        response(b'{"hostname":"fw"}'),
        response(b"[]"),
        response(b'{"data":[]}'),
        response(b'{"data":[]}'),
        response(b'{"data":[]}'),
    ]
    with patch("openshield.integrations.pfsense.build_opener", return_value=opener):
        result = client.diagnostics()
    assert set(result) == {"system", "interfaces", "arp", "dhcp_leases", "gateways"}
    assert all(call.args[0].get_method() == "GET" for call in opener.open.call_args_list)
