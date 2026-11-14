import json
from pathlib import Path
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
            {"interface": "lan", "up": True, "device": "br-lan", "proto": "static",
             "ipv4-address": [{"address": "192.0.2.1"}]}
        ]}]),
    ]
    with patch("openshield.integrations.openwrt_rpc.urlopen", side_effect=replies) as mocked:
        client = OpenWrtRPCClient(
            "http://192.0.2.1", "openshield", "test-password", timeout=3
        )
        result = client.discover()

    assert result["board"]["hostname"] == "router"
    assert result["interfaces"][0]["name"] == "lan"
    assert result["interfaces"][0]["ipv4_address"] == ["192.0.2.1"]
    assert mocked.call_count == 3
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


def test_openwrt_firewall_block_and_unblock_use_narrow_rpc_methods() -> None:
    replies = [
        response([0, {"ubus_rpc_session": "session-id"}]),
        response([0, {"status": "blocked", "ip": "8.8.8.8", "ttl_seconds": 300}]),
        response([0, {"status": "unblocked", "ip": "8.8.8.8"}]),
    ]
    with patch("openshield.integrations.openwrt_rpc.urlopen", side_effect=replies) as mocked:
        client = OpenWrtRPCClient("https://192.0.2.1", "openshield", "secret")
        blocked = client.block_ip("8.8.8.8", 300)
        unblocked = client.unblock_ip("8.8.8.8")
    assert blocked["status"] == "blocked"
    assert unblocked["status"] == "unblocked"
    block_call = json.loads(mocked.call_args_list[1].args[0].data)
    unblock_call = json.loads(mocked.call_args_list[2].args[0].data)
    assert block_call[1:3] == ["openshield-firewall", "block_ip"]
    assert block_call[3] == {"ip": "8.8.8.8", "ttl_seconds": 300}
    assert unblock_call[1:3] == ["openshield-firewall", "unblock_ip"]


def test_openwrt_firewall_rejects_private_ipv4_and_invalid_ttl() -> None:
    client = OpenWrtRPCClient("https://192.0.2.1", "openshield", "secret")
    with pytest.raises(ValueError, match="public IPv4"):
        client.block_ip("192.168.1.10", 300)
    with pytest.raises(ValueError, match="TTL"):
        client.block_ip("8.8.8.8", 30)
    with pytest.raises(ValueError, match="public IPv4"):
        client.unblock_ip("10.0.0.1")


def test_openwrt_rpc_plugin_script_has_valid_shell_syntax() -> None:
    import subprocess

    plugin = Path(__file__).resolve().parents[2] / "scripts/openwrt/openshield-firewall"
    subprocess.run(["sh", "-n", str(plugin)], check=True)
