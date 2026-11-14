import json
from unittest.mock import MagicMock, patch

import pytest

from openshield.integrations.openwrt_rpc import OpenWrtRPCClient, OpenWrtRPCError


def response(payload: object) -> MagicMock:
    result = MagicMock()
    result.__enter__.return_value.read.return_value = json.dumps(payload).encode()
    return result


def test_openwrt_rpc_authenticates_and_discovers_read_only_data() -> None:
    replies = [
        response([0, {"ubus_rpc_session": "session-id"}]),
        response([0, {"hostname": "router", "model": "OpenWrt test", "release": {"version": "24.10"}}]),
        response([0, {"interface": [
            {"interface": "lan", "up": True, "device": "br-lan", "l3_device": "br-lan",
             "proto": "static", "ipv4-address": [{"address": "192.0.2.1"}]}
        ]}]),
        response([0, {
            "AA:BB:CC:DD:EE:FF": {"name": "workstation"},
            "11:22:33:44:55:66": {"name": "phone"},
        }]),
        response([0, {"neighbors":
            "192.0.2.10 dev br-lan lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"
            "192.0.2.11 dev br-lan lladdr 11:22:33:44:55:66 STALE\n"
            "192.0.2.12 dev br-lan FAILED"
        }]),
    ]
    with patch("openshield.integrations.openwrt_rpc.urlopen", side_effect=replies) as mocked:
        client = OpenWrtRPCClient(
            "http://192.0.2.1", "openshield", "test-password", timeout=3
        )
        result = client.discover()

    assert result["board"]["hostname"] == "router"
    assert result["board"]["release"]["version"] == "24.10"
    assert result["interfaces"][0]["name"] == "lan"
    assert result["interfaces"][0]["ipv4_address"] == ["192.0.2.1"]
    assert result["devices"] == [
        {
            "mac_address": "11:22:33:44:55:66", "name": "phone",
            "ip_address": "192.0.2.11", "ipv4_addresses": ["192.0.2.11"],
            "device": "br-lan", "interface": "lan", "source": "ipv4_neighbor",
        },
        {
            "mac_address": "aa:bb:cc:dd:ee:ff", "name": "workstation",
            "ip_address": "192.0.2.10", "ipv4_addresses": ["192.0.2.10"],
            "device": "br-lan", "interface": "lan", "source": "ipv4_neighbor",
        },
    ]
    assert mocked.call_count == 5
    login = json.loads(mocked.call_args_list[0].args[0].data)
    assert login[2] == "login"
    assert login[3]["password"] == "test-password"
    assert "Authorization" not in mocked.call_args_list[1].args[0].headers


def test_openwrt_rpc_rejects_invalid_configuration() -> None:
    with pytest.raises(ValueError, match="absolute HTTP"):
        OpenWrtRPCClient("http://user:pass@router", "user", "password")
    with pytest.raises(ValueError, match="username and password"):
        OpenWrtRPCClient("http://router", "", "password")
    with pytest.raises(ValueError, match="timeout"):
        OpenWrtRPCClient("http://router", "user", "password", timeout=60)


def test_openwrt_rpc_rejects_ubus_errors_without_leaking_credentials() -> None:
    with (
        patch("openshield.integrations.openwrt_rpc.urlopen", return_value=response([6, {}])),
        pytest.raises(OpenWrtRPCError, match="rejected"),
    ):
        OpenWrtRPCClient("http://router", "user", "secret-value").login()


def test_openwrt_rpc_rejects_invalid_payload() -> None:
    with (
        patch("openshield.integrations.openwrt_rpc.urlopen", return_value=response({"bad": "shape"})),
        pytest.raises(OpenWrtRPCError, match="invalid payload"),
    ):
        OpenWrtRPCClient("http://router", "user", "password").login()


def test_openwrt_neighbor_parser_aggregates_addresses_and_ignores_invalid_rows() -> None:
    interfaces = [{"name": "lan", "device": "br-lan", "l3_device": "br-lan"}]
    hints = {"aa:bb:cc:dd:ee:ff": "desktop"}
    devices = OpenWrtRPCClient._parse_ipv4_neighbors(
        "192.0.2.10 dev br-lan lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"
        "192.0.2.11 dev br-lan lladdr aa:bb:cc:dd:ee:ff STALE\n"
        "192.0.2.12 dev br-lan FAILED\n"
        "not-an-ip dev br-lan lladdr aa:bb:cc:dd:ee:ff REACHABLE",
        hints,
        interfaces,
    )
    assert len(devices) == 1
    assert devices[0]["name"] == "desktop"
    assert devices[0]["ipv4_addresses"] == ["192.0.2.10", "192.0.2.11"]
    assert devices[0]["interface"] == "lan"


def test_openwrt_discovery_requires_host_hints_and_neighbor_rpc() -> None:
    with (
        patch(
            "openshield.integrations.openwrt_rpc.urlopen",
            side_effect=[
                response([0, {"ubus_rpc_session": "session-id"}]),
                response([0, {"hostname": "router"}]),
                response([0, {"interface": []}]),
                response([6, {}]),
            ],
        ),
        pytest.raises(OpenWrtRPCError, match="rejected"),
    ):
        OpenWrtRPCClient("http://router", "user", "password").discover()
