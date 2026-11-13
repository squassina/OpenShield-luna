import ipaddress
import json
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


class OpenWrtRPCError(RuntimeError):
    """Safe, credential-free OpenWrt RPC failure."""


class OpenWrtRPCClient:
    """OpenWrt rpcd ubus client with read-only discovery and scoped firewall writes."""

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

    def apply_firewall_block(
        self, execution_id: str, ip_value: str, direction: str
    ) -> dict[str, object]:
        try:
            address = ipaddress.ip_address(ip_value)
        except ValueError as exc:
            raise ValueError("Firewall block requires a valid IP address") from exc
        if not address.is_global:
            raise ValueError("Firewall block accepts public IP addresses only")
        if direction not in {"source", "destination"}:
            raise ValueError("Firewall block direction must be source or destination")
        section = "os_" + re.sub(r"[^a-f0-9]", "", execution_id.lower())[:16]
        values: dict[str, object] = {
            "name": f"OpenShield {section}",
            "proto": "all",
            "target": "REJECT",
            "family": "ipv4" if address.version == 4 else "ipv6",
            "enabled": "1",
        }
        if direction == "source":
            values.update({"src": "wan", "dest": "lan", "src_ip": str(address)})
        else:
            values.update({"src": "lan", "dest": "wan", "dest_ip": str(address)})
        try:
            created = self.call(
                "uci", "add",
                {"config": "firewall", "type": "rule", "name": section, "values": values},
            )
            if isinstance(created.get("section"), str):
                section = created["section"]
        except OpenWrtRPCError as exc:
            try:
                existing = self.call("uci", "get", {"config": "firewall", "section": section})
            except OpenWrtRPCError:
                raise exc
            if isinstance(existing, dict) and isinstance(existing.get("values"), dict):
                return {"section": section, "verified": True, "already_present": True}
            raise exc
        try:
            self.call("uci", "apply", {"rollback": True, "timeout": 30})
            verified = self.call("uci", "get", {"config": "firewall", "section": section})
            if not isinstance(verified, dict) or not isinstance(verified.get("values"), dict):
                raise OpenWrtRPCError("OpenWrt firewall rule verification failed")
            self.call("uci", "confirm", {})
        except OpenWrtRPCError:
            try:
                self.call("uci", "revert", {"config": "firewall"})
            except OpenWrtRPCError:
                pass
            raise
        return {"section": section, "verified": True, "already_present": False}

    def remove_firewall_block(self, section: str) -> dict[str, object]:
        if not re.fullmatch(r"os_[a-f0-9]{1,16}", section):
            raise ValueError("Invalid OpenShield firewall section")
        try:
            self.call("uci", "delete", {"config": "firewall", "section": section})
        except OpenWrtRPCError as exc:
            current = self.call("uci", "get", {"config": "firewall"})
            values = current.get("values")
            if isinstance(values, dict) and section not in values:
                return {"section": section, "removed": True, "already_absent": True}
            raise exc
        try:
            self.call("uci", "apply", {"rollback": True, "timeout": 30})
            current = self.call("uci", "get", {"config": "firewall"})
            values = current.get("values")
            if not isinstance(values, dict) or section in values:
                raise OpenWrtRPCError("OpenWrt firewall rule rollback verification failed")
            self.call("uci", "confirm", {})
        except OpenWrtRPCError:
            try:
                self.call("uci", "revert", {"config": "firewall"})
            except OpenWrtRPCError:
                pass
            raise
        return {"section": section, "removed": True, "already_absent": False}

    def health_check(self) -> dict[str, object]:
        board = self.call("system", "board")
        return {
            "status": "reachable",
            "hostname": board.get("hostname"),
            "model": board.get("model"),
        }
