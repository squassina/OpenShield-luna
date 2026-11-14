import ipaddress
import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


class OpenWrtRPCError(RuntimeError):
    """Safe, credential-free OpenWrt RPC failure."""


class OpenWrtRPCClient:
    """Read-only client for the OpenWrt rpcd ubus HTTP endpoint."""

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        timeout: float = 5.0,
    ) -> None:
        parsed = urlsplit(base_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("OpenWrt URL must be an absolute HTTP(S) URL without credentials")
        if not username or not password:
            raise ValueError("OpenWrt RPC username and password are required")
        if not 0 < timeout <= 30:
            raise ValueError("OpenWrt RPC timeout must be between 0 and 30 seconds")
        self._endpoint = f"{base_url.rstrip('/')}/ubus"
        self._username = username
        self._password = password
        self._timeout = timeout
        self._session: str | None = None

    def _request(self, payload: list[object]) -> object:
        request = Request(
            self._endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=self._timeout) as response:
                raw = response.read(1_048_577)
        except HTTPError as exc:
            raise OpenWrtRPCError(f"OpenWrt RPC returned HTTP {exc.code}") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise OpenWrtRPCError("Unable to reach OpenWrt RPC endpoint") from exc
        if len(raw) > 1_048_576:
            raise OpenWrtRPCError("OpenWrt RPC response exceeded the size limit")
        try:
            result = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OpenWrtRPCError("OpenWrt RPC returned invalid JSON") from exc
        if (
            not isinstance(result, list)
            or len(result) != 2
            or result[0] != 0
            or not isinstance(result[1], dict)
        ):
            raise OpenWrtRPCError("OpenWrt RPC rejected the request or returned an invalid payload")
        return result[1]

    def login(self) -> None:
        result = self._request(
            [
                "00000000000000000000000000000000",
                "session",
                "login",
                {"username": self._username, "password": self._password, "timeout": 300},
            ]
        )
        session = result.get("ubus_rpc_session")
        if not isinstance(session, str) or not session:
            raise OpenWrtRPCError("OpenWrt RPC authentication response was invalid")
        self._session = session

    def call(self, object_name: str, method: str, params: dict[str, object] | None = None) -> dict:
        if self._session is None:
            self.login()
        result = self._request(
            [self._session, object_name, method, params or {}]
        )
        return result

    def discover(self) -> dict[str, object]:
        board = self.call("system", "board")
        interfaces = self.call("network.interface", "dump")
        raw_interfaces = interfaces.get("interface", [])
        if not isinstance(raw_interfaces, list):
            raise OpenWrtRPCError("OpenWrt interface discovery response was invalid")
        normalized_interfaces = []
        for item in raw_interfaces:
            if not isinstance(item, dict):
                continue
            addresses = item.get("ipv4-address", [])
            if not isinstance(addresses, list):
                addresses = []
            normalized_interfaces.append(
                {
                    "name": item.get("interface"),
                    "up": item.get("up"),
                    "device": item.get("device"),
                    "proto": item.get("proto"),
                    "ipv4_address": [
                        address.get("address")
                        for address in addresses
                        if isinstance(address, dict) and isinstance(address.get("address"), str)
                    ],
                }
            )
        return {
            "board": {
                key: board.get(key)
                for key in ("hostname", "model", "system", "kernel", "release")
                if isinstance(board.get(key), (str, int, float, bool)) or board.get(key) is None
            },
            "interfaces": normalized_interfaces,
        }

    def block_ip(self, ip_value: str, ttl_seconds: int) -> dict[str, object]:
        try:
            address = ipaddress.ip_address(ip_value)
        except ValueError as exc:
            raise ValueError("Firewall action requires a valid public IPv4 address") from exc
        if address.version != 4 or not address.is_global:
            raise ValueError("Firewall action accepts public IPv4 addresses only")
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or not 60 <= ttl_seconds <= 604800:
            raise ValueError("Firewall block TTL must be between 60 and 604800 seconds")
        result = self.call(
            "openshield-firewall", "block_ip",
            {"ip": str(address), "ttl_seconds": ttl_seconds},
        )
        if (
            result.get("status") not in {"blocked", "already_blocked"}
            or result.get("ip") != str(address)
            or result.get("ttl_seconds") != ttl_seconds
        ):
            raise OpenWrtRPCError("OpenWrt firewall plugin returned an invalid block result")
        return result

    def unblock_ip(self, ip_value: str) -> dict[str, object]:
        try:
            address = ipaddress.ip_address(ip_value)
        except ValueError as exc:
            raise ValueError("Firewall action requires a valid public IPv4 address") from exc
        if address.version != 4 or not address.is_global:
            raise ValueError("Firewall action accepts public IPv4 addresses only")
        result = self.call(
            "openshield-firewall", "unblock_ip", {"ip": str(address)},
        )
        if result.get("status") != "unblocked" or result.get("ip") != str(address):
            raise OpenWrtRPCError("OpenWrt firewall plugin returned an invalid unblock result")
        return result

    def firewall_health_check(self) -> dict[str, object]:
        result = self.call("openshield-firewall", "status")
        if result.get("status") != "ready" or result.get("set") != "oshield_v4":
            raise OpenWrtRPCError("OpenWrt firewall plugin readiness response was invalid")
        return result

    def health_check(self) -> dict[str, object]:
        board = self.call("system", "board")
        try:
            firewall = self.firewall_health_check()
        except OpenWrtRPCError:
            firewall = {"status": "unavailable", "reason": "plugin_unavailable"}
        return {
            "status": "reachable",
            "hostname": board.get("hostname"),
            "model": board.get("model"),
            "firewall_enforcement": firewall,
        }
