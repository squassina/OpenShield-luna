from unittest.mock import patch

import pytest

from openshield.integrations.opnsense import OPNsenseClient, OPNsenseError


def test_opnsense_client_uses_basic_auth_and_get_only():
    client = OPNsenseClient("https://firewall.example", "key", "secret")
    response = type("Response", (), {
        "__enter__": lambda self: self,
        "__exit__": lambda self, *args: None,
        "read": lambda self, size: b'{"status":"ok"}',
    })()
    with patch("openshield.integrations.opnsense.urlopen", return_value=response) as request:
        assert client.get("/api/diagnostics/system/system_information") == {"status": "ok"}
    sent = request.call_args.args[0]
    assert sent.get_method() == "GET"
    assert sent.get_header("Authorization").startswith("Basic ")


@pytest.mark.parametrize("url", ["", "ftp://host", "https://user:pass@host", "https://host/path?q=1"])
def test_opnsense_rejects_invalid_base_url(url):
    with pytest.raises(ValueError):
        OPNsenseClient(url, "key", "secret")


def test_opnsense_rejects_non_api_path():
    client = OPNsenseClient("https://firewall.example", "key", "secret")
    with pytest.raises(ValueError):
        client.get("/api/../etc/passwd")


def test_opnsense_rejects_invalid_json():
    client = OPNsenseClient("https://firewall.example", "key", "secret")
    response = type("Response", (), {
        "__enter__": lambda self: self,
        "__exit__": lambda self, *args: None,
        "read": lambda self, size: b"not-json",
    })()
    with (
        patch("openshield.integrations.opnsense.urlopen", return_value=response),
        pytest.raises(OPNsenseError, match="invalid JSON"),
    ):
        client.get("/api/diagnostics/system/system_information")
