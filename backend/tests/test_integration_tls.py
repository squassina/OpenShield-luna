import ssl
from unittest.mock import Mock, patch
from urllib.request import HTTPSHandler

import pytest

from openshield.integrations import (
    crowdsec,
    grafana,
    misp,
    openwrt_rpc,
    opnsense,
    pfsense,
    prometheus,
    wazuh,
)


class FakeResponse:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, _size: int) -> bytes:
        return self.payload


@pytest.mark.parametrize(
    ("module", "client", "invoke", "payload"),
    [
        (
            pfsense,
            lambda context: pfsense.PfSenseClient(
                "https://firewall.example", "api-key", ssl_context=context
            ),
            lambda client: client.get("/api/v2/status/system"),
            b"{}",
        ),
        (
            misp,
            lambda context: misp.MispClient(
                "https://misp.example", "api-key", ssl_context=context
            ),
            lambda client: client.diagnostics(),
            b'{"version":"2.4.1"}',
        ),
        (
            wazuh,
            lambda context: wazuh.WazuhClient(
                "https://wazuh.example:55000", "reader", "password",
                ssl_context=context,
            ),
            lambda client: client._request("/", "GET", {}),
            b"{}",
        ),
        (
            grafana,
            lambda context: grafana.GrafanaClient(
                "https://grafana.example", ssl_context=context
            ),
            lambda client: client._get("/api/health"),
            b"{}",
        ),
        (
            prometheus,
            lambda context: prometheus.PrometheusClient(
                "https://prometheus.example", ssl_context=context
            ),
            lambda client: client._get("/api/v1/status/runtimeinfo"),
            b'{"status":"success","data":{}}',
        ),
        (
            crowdsec,
            lambda context: crowdsec.CrowdSecClient(
                "https://crowdsec.example", "bouncer-key", ssl_context=context
            ),
            lambda client: client._request("/v1/decisions", "GET", {}),
            b"[]",
        ),
    ],
)
def test_integration_clients_install_custom_https_context(
    module, client, invoke, payload: bytes
) -> None:
    context = ssl.create_default_context()
    opener = Mock()
    opener.open.return_value = FakeResponse(payload)

    with patch.object(module, "build_opener", return_value=opener) as build_opener:
        invoke(client(context))

    handler = next(
        item for item in build_opener.call_args.args
        if isinstance(item, HTTPSHandler)
    )
    assert handler._context is context


@pytest.mark.parametrize(
    ("module", "client", "invoke", "payload"),
    [
        (
            openwrt_rpc,
            lambda context: openwrt_rpc.OpenWrtRPCClient(
                "https://router.example", "rpc", "password", ssl_context=context
            ),
            lambda client: client._request(["session", "system", "board", {}]),
            b"[0,{}]",
        ),
        (
            opnsense,
            lambda context: opnsense.OPNsenseClient(
                "https://firewall.example", "api-key", "api-secret",
                ssl_context=context,
            ),
            lambda client: client.get("/api/diagnostics/system/system_information"),
            b"{}",
        ),
    ],
)
def test_safe_transport_receives_custom_https_context(
    module, client, invoke, payload: bytes
) -> None:
    context = ssl.create_default_context()
    with patch.object(module, "urlopen", return_value=FakeResponse(payload)) as urlopen:
        invoke(client(context))

    assert urlopen.call_args.kwargs["context"] is context
