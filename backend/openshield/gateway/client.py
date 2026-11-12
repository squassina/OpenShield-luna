import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from openshield.gateway.models import GatewayConnectRequest


class GatewayTransportError(RuntimeError):
    pass


class GatewayConnectorClient:
    """Outbound, TLS-verifying client for the Node gateway protocol."""

    def __init__(
        self,
        node_url: str,
        gateway_id: str,
        api_key: str,
        connector_version: str = "0.1.0",
        timeout: float = 10.0,
    ) -> None:
        parsed = urlsplit(node_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("Node URL must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Node URL must not contain credentials, query, or fragment")
        if len(api_key) < 32:
            raise ValueError("Gateway API key must contain at least 32 characters")
        if not gateway_id:
            raise ValueError("Gateway ID is required")
        self._base_url = node_url.rstrip("/")
        self._gateway_id = gateway_id
        self._api_key = api_key
        self._connector_version = connector_version
        self._timeout = timeout

    def connect(self) -> dict[str, object]:
        request = GatewayConnectRequest(
            protocol_version="openshield.gateway.v1",
            gateway_id=self._gateway_id,
            gateway_type="openwrt",
            connector_version=self._connector_version,
            capabilities=["discover", "health_check", "read_events"],
        )
        return self._post("/api/v1/gateway/connect", request.model_dump(mode="json"))

    def heartbeat(self) -> dict[str, object]:
        return self._post(
            "/api/v1/gateway/heartbeat",
            {"protocol_version": "openshield.gateway.v1"},
        )

    def _post(self, path: str, payload: dict[str, object]) -> dict[str, object]:
        request = Request(
            f"{self._base_url}{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=self._timeout) as response:
                result = json.loads(response.read())
        except HTTPError as exc:
            raise GatewayTransportError(f"Node rejected gateway request (HTTP {exc.code})") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise GatewayTransportError("Unable to reach OpenShield Node") from exc
        except json.JSONDecodeError as exc:
            raise GatewayTransportError("Node returned an invalid JSON response") from exc

        if not isinstance(result, dict):
            raise GatewayTransportError("Node returned an invalid response")
        return result
