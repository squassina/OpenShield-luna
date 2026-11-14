import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from openshield.events.models import EventEnvelope
from openshield.gateway.models import GatewayConnectRequest
from openshield.integrations.models import Capability


class GatewayTransportError(RuntimeError):
    pass


class GatewayConnectorClient:
    """Outbound, TLS-verifying client for the Node gateway protocol."""

    def __init__(
        self,
        node_url: str,
        gateway_id: str,
        connector_version: str = "0.1.0",
        timeout: float = 10.0,
        capabilities: list[Capability] | None = None,
        gateway_token: str | None = None,
    ) -> None:
        parsed = urlsplit(node_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("Node URL must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Node URL must not contain credentials, query, or fragment")
        if not gateway_id:
            raise ValueError("Gateway ID is required")
        self._base_url = node_url.rstrip("/")
        self._gateway_id = gateway_id
        self._connector_version = connector_version
        self._timeout = timeout
        self._capabilities = capabilities or []
        self._gateway_token = gateway_token or ""

    def connect(self) -> dict[str, object]:
        request = GatewayConnectRequest(
            protocol_version="openshield.gateway.v1",
            gateway_id=self._gateway_id,
            gateway_type="openwrt",
            connector_version=self._connector_version,
            capabilities=self._capabilities,
        )
        return self._post("/api/v1/gateway/connect", request.model_dump(mode="json"))

    def heartbeat(self) -> dict[str, object]:
        return self._post(
            "/api/v1/gateway/heartbeat",
            {"protocol_version": "openshield.gateway.v1", "gateway_id": self._gateway_id},
        )

    def ingest_event(self, event: EventEnvelope) -> dict[str, object]:
        return self._post("/api/v1/events", event.model_dump(mode="json"))

    def report_action_result(
        self, action_id: str, status: str, result: dict[str, object] | None = None,
        error: str | None = None,
    ) -> dict[str, object]:
        return self._post(
            f"/api/v1/gateway/actions/{action_id}/result",
            {"gateway_id": self._gateway_id, "status": status, "result": result or {}, "error": error},
        )

    def _post(self, path: str, payload: dict[str, object]) -> dict[str, object]:
        request = Request(
            f"{self._base_url}{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                **({"Authorization": f"Bearer {self._gateway_token}"} if self._gateway_token else {}),
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
