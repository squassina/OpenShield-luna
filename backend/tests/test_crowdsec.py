from unittest.mock import Mock, patch

import pytest

from openshield.integrations.crowdsec import CrowdSecClient, CrowdSecError


def response(payload: bytes):
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, size):
            assert size == CrowdSecClient.MAX_RESPONSE_BYTES + 1
            return payload

    return FakeResponse()


def test_crowdsec_reads_alerts_and_decisions_with_separate_credentials():
    client = CrowdSecClient(
        "https://crowdsec.example",
        "bouncer-key",
        "machine-reader",
        "machine-password",
    )
    opener = Mock()
    opener.open.side_effect = [
        response(b'{"token":"session-token"}'),
        response(b'[{"id":1,"scenario":"ssh-bf"}]'),
        response(b'[{"type":"ban","scope":"Ip","value":"192.0.2.10"}]'),
    ]
    with patch("openshield.integrations.crowdsec.build_opener", return_value=opener):
        result = client.diagnostics()

    requests = [call.args[0] for call in opener.open.call_args_list]
    assert [request.get_method() for request in requests] == ["POST", "GET", "GET"]
    assert requests[0].full_url.endswith("/v1/watchers/login")
    assert requests[1].full_url.endswith("/v1/alerts?limit=100")
    assert requests[1].get_header("Authorization") == "Bearer session-token"
    assert requests[2].full_url.endswith("/v1/decisions")
    assert requests[2].get_header("X-api-key") == "bouncer-key"
    assert result["summary"] == {
        "alerts_available": 1,
        "decisions_available": 1,
        "alerts_auth_configured": True,
    }


def test_crowdsec_can_read_decisions_without_watcher_credentials():
    client = CrowdSecClient("https://crowdsec.example", "bouncer-key")
    opener = Mock()
    opener.open.return_value = response(b"[]")
    with patch("openshield.integrations.crowdsec.build_opener", return_value=opener):
        result = client.diagnostics()
    request = opener.open.call_args.args[0]
    assert request.get_method() == "GET"
    assert request.full_url.endswith("/v1/decisions")
    assert result["alerts"] is None
    assert result["summary"]["alerts_available"] is None
    assert result["summary"]["decisions_available"] == 0


@pytest.mark.parametrize(
    "url",
    ["", "ftp://host", "https://user:pass@host", "https://host/path", "https://host/?q=1"],
)
def test_crowdsec_rejects_invalid_base_url(url):
    with pytest.raises(ValueError):
        CrowdSecClient(url, "bouncer-key")


def test_crowdsec_rejects_invalid_credentials_and_header_injection():
    with pytest.raises(ValueError, match="supplied together"):
        CrowdSecClient("https://crowdsec.example", "bouncer-key", "machine-id")
    with pytest.raises(ValueError, match="API key"):
        CrowdSecClient("https://crowdsec.example", "bad\r\nX-Injected: yes")


def test_crowdsec_rejects_invalid_login_response():
    client = CrowdSecClient(
        "https://crowdsec.example", "bouncer-key", "machine-reader", "machine-password"
    )
    opener = Mock()
    opener.open.side_effect = [response(b'{"code":403}')]
    with (
        patch("openshield.integrations.crowdsec.build_opener", return_value=opener),
        pytest.raises(CrowdSecError, match="no session token"),
    ):
        client.diagnostics()


def test_crowdsec_rejects_oversized_response():
    client = CrowdSecClient("https://crowdsec.example", "bouncer-key")
    opener = Mock()
    opener.open.return_value = response(b"x" * (CrowdSecClient.MAX_RESPONSE_BYTES + 1))
    with (
        patch("openshield.integrations.crowdsec.build_opener", return_value=opener),
        pytest.raises(CrowdSecError, match="size limit"),
    ):
        client.diagnostics()
