import os
from typing import ClassVar

from openshield.integrations.models import Capability, Integration
from openshield.integrations.openwrt_rpc import OpenWrtRPCClient


class OpenWrtAdapter:
    """Read-only OpenWrt adapter. It never changes firewall or forwarding state."""

    kind = "openwrt"
    capabilities: ClassVar[list[Capability]] = [
        Capability.HEALTH_CHECK,
        Capability.DISCOVER,
    ]

    def _client(self, integration: Integration) -> OpenWrtRPCClient:
        base_url = integration.config.get("base_url")
        if not isinstance(base_url, str):
            raise TypeError("OpenWrt integration requires a string base_url")
        return OpenWrtRPCClient(
            base_url=base_url,
            username=os.getenv("OPENSHIELD_OPENWRT_USERNAME", ""),
            password=os.getenv("OPENSHIELD_OPENWRT_PASSWORD", ""),
        )

    def probe(self, integration: Integration) -> dict[str, object]:
        return {
            "integration_id": integration.integration_id,
            "kind": self.kind,
            "status": "configured",
            "transport": "ubus_rpc",
            "capabilities": [capability.value for capability in self.capabilities],
        }

    def discover(self, integration: Integration) -> dict[str, object]:
        return self._client(integration).discover()

    def health_check(self, integration: Integration) -> dict[str, object]:
        return self._client(integration).health_check()
