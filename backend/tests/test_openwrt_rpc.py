import json
from unittest.mock import MagicMock, patch

import pytest

from openshield.integrations.openwrt_rpc import OpenWrtRPCClient, OpenWrtRPCError


def response(payload: object) -> MagicMock:
    result = MagicMock()
    result.__enter__.return_value.read.return_value = json.dumps(payload).encode()
    return result


def test_openwrt_rpc_discovers_devices_from_standard_luci_methods() -> None:
    replies = [
        response([0, {"ubus_rpc_session": "session-id"}]),
        response([0, {"hostname": "router", "model": "OpenWrt test", "release": {"version": "24.10"}}]),
        response([0, {"interface": [
            {"interface": "lan", "up": True, "device": "br-lan", "l3_device": "br-lan",
             "proto": "static", "ipv4-address": [{"address": "192.0.2.1"}]}
        ]}]),
        response([0, {
            "AA:BB:CC:DD:EE:FF": {
                "name": "workstation",
                "ipaddrs": ["192.0.2.10"],
                "ip6addrs": ["2001:db8::10"],
            },
            "11:22:33:44:55:66": {"ipaddrs": ["192.0.2.11"]},
        }]),
        response([0, {"dhcp_leases": [
            {"macaddr": "11:22:33:44:55:66", "hostname": "phone",
             "ipaddr": "192.0.2.11", "interface": "lan", "expires": 120}
        ], "dhcp6_leases": []}]),
    ]
    with patch("openshield.integrations.openwrt_rpc.urlopen", side_effect=replies) as mocked:
        client = OpenWrtRPCClient("http://192.0.2.1", "openshield", "test-password", timeout=3)
        result = client.discover()

    assert result["board"]["hostname"] == "router"
    assert result["interfaces"][0]["name"] == "lan"
    assert result["devices"] == [
        {
            "mac_address": "11:22:33:44:55:66", "name": "phone",
            "ip_address": "192.0.2.11", "ipv4_addresses": ["192.0.2.11"],
            "ipv6_addresses": [], "device": "lan", "interface": "lan", "source": "luci-rpc",
        },
        {
            "mac_address": "aa:bb:cc:dd:ee:ff", "name": "workstation",
            "ip_address": "192.0.2.10", "ipv4_addresses": ["192.0.2.10"],
            "ipv6_addresses": ["2001:db8::10"], "device": "", "interface": "Unmapped",
            "source": "luci-rpc",
        },
    ]
    assert mocked.call_count == 5
    calls = [json.loads(call.args[0].data) for call in mocked.call_args_list]
    assert calls[0][2] == "login"
    assert calls[0][3]["password"] == "test-password"
    assert calls[3][1:3] == ["luci-rpc", "getHostHints"]
    assert calls[4][1:3] == ["luci-rpc", "getDHCPLeases"]


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


def test_luci_host_hints_and_dhcp_leases_merge_by_mac() -> None:
    devices = OpenWrtRPCClient._parse_devices(
        {
            "AA:BB:CC:DD:EE:FF": {
                "name": "desktop", "ipaddrs": ["192.0.2.10"],
                "ip6addrs": ["2001:db8::10/64"],
            }
        },
        {
            "dhcp_leases": [
                {"macaddr": "aa:bb:cc:dd:ee:ff", "hostname": "ignored",
                 "ipaddr": "192.0.2.11", "interface": "lan"},
            ],
            "dhcp6_leases": [],
        },
    )
    assert len(devices) == 1
    assert devices[0]["name"] == "desktop"
    assert devices[0]["ipv4_addresses"] == ["192.0.2.10", "192.0.2.11"]
    assert devices[0]["ipv6_addresses"] == ["2001:db8::10"]
    assert devices[0]["interface"] == "lan"


def test_luci_device_parser_ignores_invalid_macs_and_addresses() -> None:
    devices = OpenWrtRPCClient._parse_devices(
        {"not-a-mac": {"name": "bad", "ipaddrs": ["192.0.2.1"]}},
        {"dhcp_leases": [
            {"macaddr": "aa:bb:cc:dd:ee:ff", "ipaddr": "999.0.0.1"},
        ], "dhcp6_leases": []},
    )
    assert len(devices) == 1
    assert devices[0]["ip_address"] == ""
    assert devices[0]["interface"] == "Unmapped"
