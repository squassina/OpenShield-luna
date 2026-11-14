import ipaddress
import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


def _valid_mac(value: object) -> bool:
    if not isinstance(value, str):
        return False
    parts = value.split(":")
    return len(parts) == 6 and all(
        len(part) == 2 and all(character in "0123456789abcdefABCDEF" for character in part)
        for part in parts
    )


def _valid_ip(value: object, version: int) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return ipaddress.ip_address(value).version == version
    except ValueError:
        return False


class OpenWrtRPCError(RuntimeError):
    """Safe, credential-free OpenWrt RPC failure."""


class OpenWrtRPCClient:
    """Read-only client for the standard OpenWrt LuCI ubus HTTP endpoint."""

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

    def _request(self, payload: list[object]) -> dict[str, object]:
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

    def call(
        self,
        object_name: str,
        method: str,
        params: dict[str, object] | None = None,
    ) -> dict[str, object]:
        if self._session is None:
            self.login()
        return self._request([self._session, object_name, method, params or {}])

    @staticmethod
    def _parse_devices(
        hints: object,
        leases: object,
    ) -> list[dict[str, object]]:
        if not isinstance(hints, dict):
            raise OpenWrtRPCError("OpenWrt host hints response was invalid")

        devices: dict[str, dict[str, object]] = {}

        def get_device(mac_value: object) -> dict[str, object] | None:
            if not isinstance(mac_value, str) or not _valid_mac(mac_value):
                return None
            mac = mac_value.lower()
            return devices.setdefault(mac, {
                "mac_address": mac,
                "name": "(sem-nome)",
                "ip_address": "",
                "ipv4_addresses": [],
                "ipv6_addresses": [],
                "device": "",
                "interface": "Unmapped",
                "source": "luci-rpc",
            })

        for mac, hint in hints.items():
            item = get_device(mac)
            if item is None or not isinstance(hint, dict):
                continue
            name = hint.get("name")
            if isinstance(name, str) and name.strip():
                item["name"] = name.strip()[:128]
            for field, version in (("ipaddrs", 4), ("ip6addrs", 6)):
                addresses = hint.get(field, [])
                if not isinstance(addresses, list):
                    continue
                target = item["ipv4_addresses"] if version == 4 else item["ipv6_addresses"]
                for address in addresses:
                    if isinstance(address, str):
                        address = address.split("/", 1)[0]
                    if _valid_ip(address, version) and address not in target:
                        target.append(address)
            if item["ipv4_addresses"]:
                item["ip_address"] = item["ipv4_addresses"][0]

        if not isinstance(leases, dict):
            raise OpenWrtRPCError("OpenWrt DHCP leases response was invalid")
        for field, address_field, version in (
            ("dhcp_leases", "ipaddr", 4),
            ("dhcp6_leases", "ip6addr", 6),
        ):
            rows = leases.get(field, [])
            if not isinstance(rows, list):
                continue
            for lease in rows:
                if not isinstance(lease, dict):
                    continue
                item = get_device(lease.get("macaddr"))
                if item is None:
                    continue
                hostname = lease.get("hostname")
                if item["name"] == "(sem-nome)" and isinstance(hostname, str) and hostname.strip():
                    item["name"] = hostname.strip()[:128]
                address = lease.get(address_field)
                if isinstance(address, str) and _valid_ip(address, version):
                    target = item["ipv4_addresses"] if version == 4 else item["ipv6_addresses"]
                    if address not in target:
                        target.append(address)
                    if version == 4 and not item["ip_address"]:
                        item["ip_address"] = address
                interface = lease.get("interface")
                if isinstance(interface, str) and interface:
                    item["interface"] = interface
                    item["device"] = interface

        return sorted(
            devices.values(),
            key=lambda item: (str(item["interface"]), str(item["mac_address"])),
        )

    def discover(self) -> dict[str, object]:
        board = self.call("system", "board")
        interfaces = self.call("network.interface", "dump")
        hints = self.call("luci-rpc", "getHostHints")
        leases = self.call("luci-rpc", "getDHCPLeases")
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
            normalized_interfaces.append({
                "name": item.get("interface"),
                "up": item.get("up"),
                "device": item.get("device"),
                "l3_device": item.get("l3_device"),
                "proto": item.get("proto"),
                "ipv4_address": [
                    address.get("address") for address in addresses
                    if isinstance(address, dict) and isinstance(address.get("address"), str)
                ],
            })
        normalized_board = {
            key: board.get(key)
            for key in ("hostname", "model", "system", "kernel")
            if isinstance(board.get(key), (str, int, float, bool)) or board.get(key) is None
        }
        release = board.get("release")
        if isinstance(release, dict):
            normalized_board["release"] = {
                key: value for key, value in release.items()
                if key in {"distribution", "version", "revision", "target", "description"}
                and isinstance(value, (str, int, float, bool))
            }
        elif isinstance(release, (str, int, float, bool)) or release is None:
            normalized_board["release"] = release
        devices = self._parse_devices(hints, leases)
        return {
            "board": normalized_board,
            "interfaces": normalized_interfaces,
            "devices": devices,
            "device_discovery": {
                "source": "luci-rpc getHostHints + getDHCPLeases",
                "name_source": "luci-rpc getHostHints / getDHCPLeases",
                "interface_source": "luci-rpc getDHCPLeases",
            },
        }

    def health_check(self) -> dict[str, object]:
        board = self.call("system", "board")
        return {
            "status": "reachable",
            "hostname": board.get("hostname"),
            "model": board.get("model"),
        }
