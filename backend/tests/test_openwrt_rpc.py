import json
import threading
from concurrent.futures import ThreadPoolExecutor
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
            {
                "interface": "lan", "up": True, "device": "br-lan", "l3_device": "br-lan",
                "proto": "static", "vid": 10,
                "ipv4-address": [{"address": "192.0.2.1", "mask": 24}],
                "route": [{"target": "0.0.0.0", "mask": 0, "nexthop": "192.0.2.254"}],
            }
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
    assert result["interfaces"][0]["subnets"][0]["subnet"] == "192.0.2.0/24"
    assert result["interfaces"][0]["gateway_addresses"] == ["192.0.2.254"]
    assert result["interfaces"][0]["vlan_id"] == 10
    assert result["devices"] == [
        {
            "mac_address": "aa:bb:cc:dd:ee:ff", "name": "workstation",
            "ip_address": "192.0.2.10", "ipv4_addresses": ["192.0.2.10"],
            "ipv6_addresses": ["2001:db8::10"],
            "address_evidence": {
                "192.0.2.10": [{"source": "luci_host_hints", "confidence": "medium"}],
                "2001:db8::10": [{"source": "luci_host_hints", "confidence": "medium"}],
            },
            "vendor": None, "device": "", "interface": "Unmapped", "source": "luci-rpc",
        },
        {
            "mac_address": "11:22:33:44:55:66", "name": "phone",
            "ip_address": "192.0.2.11", "ipv4_addresses": ["192.0.2.11"],
            "ipv6_addresses": [],
            "address_evidence": {
                "192.0.2.11": [
                    {"source": "luci_host_hints", "confidence": "medium"},
                    {"source": "dhcp_lease", "confidence": "high"},
                ]
            },
            "vendor": None, "device": "", "interface": "lan", "source": "luci-rpc",
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


def test_openwrt_rpc_renews_expired_session_and_retries_once() -> None:
    replies = [
        response([0, {"ubus_rpc_session": "old-session"}]),
        response([6, {}]),
        response([0, {"ubus_rpc_session": "new-session"}]),
        response([0, {"result": "ok"}]),
    ]
    with patch("openshield.integrations.openwrt_rpc.urlopen", side_effect=replies) as mocked:
        client = OpenWrtRPCClient("http://router", "user", "password")

        assert client.call("system", "board") == {"result": "ok"}

    assert mocked.call_count == 4
    calls = [json.loads(call.args[0].data) for call in mocked.call_args_list]
    assert calls[0][2] == "login"
    assert calls[1][0] == "old-session"
    assert calls[2][2] == "login"
    assert calls[3][0] == "new-session"


def test_openwrt_rpc_surfaces_second_session_failure() -> None:
    replies = [
        response([0, {"ubus_rpc_session": "old-session"}]),
        response([6, {}]),
        response([0, {"ubus_rpc_session": "new-session"}]),
        response([6, {}]),
    ]
    with (
        patch("openshield.integrations.openwrt_rpc.urlopen", side_effect=replies) as mocked,
        pytest.raises(OpenWrtRPCError, match="no longer authorized"),
    ):
        OpenWrtRPCClient("http://router", "user", "password").call("system", "board")

    assert mocked.call_count == 4


def test_openwrt_rpc_does_not_retry_non_session_errors() -> None:
    replies = [
        response([0, {"ubus_rpc_session": "session"}]),
        response([4, {}]),
    ]
    with (
        patch("openshield.integrations.openwrt_rpc.urlopen", side_effect=replies) as mocked,
        pytest.raises(OpenWrtRPCError, match="rejected"),
    ):
        OpenWrtRPCClient("http://router", "user", "password").call("system", "board")

    assert mocked.call_count == 2


def test_openwrt_rpc_does_not_retry_invalid_credentials() -> None:
    with (
        patch(
            "openshield.integrations.openwrt_rpc.urlopen",
            return_value=response([6, {}]),
        ) as mocked,
        pytest.raises(OpenWrtRPCError, match="rejected"),
    ):
        OpenWrtRPCClient("http://router", "user", "wrong-password").call(
            "system", "board"
        )

    assert mocked.call_count == 1


def test_openwrt_rpc_concurrent_expiry_uses_one_renewed_session() -> None:
    expired_calls = threading.Barrier(2)
    state_lock = threading.Lock()
    login_count = 0

    def ubus_response(request: object, **_: object) -> MagicMock:
        nonlocal login_count
        payload = json.loads(request.data)
        if payload[2] == "login":
            with state_lock:
                login_count += 1
                session = "old-session" if login_count == 1 else "new-session"
            return response([0, {"ubus_rpc_session": session}])
        if payload[0] == "old-session":
            expired_calls.wait(timeout=3)
            return response([6, {}])
        return response([0, {"result": "ok"}])

    client = OpenWrtRPCClient("http://router", "user", "password")
    with (
        patch("openshield.integrations.openwrt_rpc.urlopen", side_effect=ubus_response),
        ThreadPoolExecutor(max_workers=2) as executor,
    ):
        results = list(executor.map(lambda _: client.call("system", "board"), range(2)))

    assert results == [{"result": "ok"}, {"result": "ok"}]
    assert login_count == 2
