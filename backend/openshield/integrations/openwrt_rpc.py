import ipaddress
import json
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


_MAC_PATTERN = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


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

    @staticmethod
    def _parse_host_hints(value: object) -> dict[str, str]:
        if not isinstance(value, dict):
            raise OpenWrtRPCError("OpenWrt host hints response was invalid")
        result = {}
        for mac, hint in value.items():
            if not isinstance(mac, str) or not _MAC_PATTERN.fullmatch(mac):
                continue
            if not isinstance(hint, dict):
                continue
            name = hint.get("name")
            if isinstance(name, str) and name.strip():
                result[mac.lower()] = name.strip()[:128]
        return result

    @staticmethod
    def _parse_ipv4_neighbors(
        output: object,
        hints: dict[str, str],
        interfaces: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        if not isinstance(output, str):
            raise OpenWrtRPCError("OpenWrt IPv4 neighbor response was invalid")
        interface_by_device: dict[str, str] = {}
        for item in interfaces:
            name = item.get("name")
            if not isinstance(name, str) or not name:
                continue
            for key in ("l3_device", "device"):
                device = item.get(key)
                if isinstance(device, str) and device:
                    interface_by_device.setdefault(device, name)

        devices: dict[str, dict[str, object]] = {}
        for line in output.splitlines():
            fields = line.split()
            if not fields:
                continue
            try:
                address = str(ipaddress.IPv4Address(fields[0]))
            except ipaddress.AddressValueError:
                continue
            device = ""
            mac = ""
            for index, field in enumerate(fields[:-1]):
                if field == "dev":
                    device = fields[index + 1]
                elif field == "lladdr":
                    mac = fields[index + 1]
            if not device or not _MAC_PATTERN.fullmatch(mac):
                continue
            mac = mac.lower()
            item = devices.setdefault(mac, {
                "mac_address": mac,
                "name": hints.get(mac, "(sem-nome)"),
                "ip_address": address,
                "ipv4_addresses": [],
                "device": device,
                "interface": interface_by_device.get(device, device),
                "source": "ipv4_neighbor",
            })
            addresses = item["ipv4_addresses"]
            if address not in addresses:
                addresses.append(address)
            item["ip_address"] = address
            item["device"] = device
            item["interface"] = interface_by_device.get(device, device)
        return sorted(devices.values(), key=lambda item: (str(item["interface"]), str(item["mac_address"])))

    def discover(self) -> dict[str, object]:
        board = self.call("system", "board")
        interfaces = self.call("network.interface", "dump")
        hints = self.call("luci-rpc", "getHostHints")
        neighbors = self.call("openshield", "get_ipv4_neighbors")
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
        host_hints = self._parse_host_hints(hints)
        devices = self._parse_ipv4_neighbors(
            neighbors.get("neighbors"), host_hints, normalized_interfaces
        )
        return {
            "board": normalized_board,
            "interfaces": normalized_interfaces,
            "devices": devices,
            "device_discovery": {
                "source": "ip -4 neigh show",
                "name_source": "luci-rpc getHostHints",
                "interface_source": "network.interface dump",
            },
        }
    def health_check(self) -> dict[str, object]:
        board = self.call("system", "board")
        return {
            "status": "reachable",
            "hostname": board.get("hostname"),
            "model": board.get("model"),
        }
