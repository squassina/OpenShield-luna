from typing import ClassVar

from openshield.integrations.models import Capability, Integration


class OpenWrtAdapter:
    """Node-side capability contract for the nearby-host OpenWrt connector."""

    kind = "openwrt"
    capabilities: ClassVar[list[Capability]] = [
        Capability.HEALTH_CHECK,
        Capability.DISCOVER,
    ]

    def probe(self, integration: Integration) -> dict[str, object]:
        return {
            "integration_id": integration.integration_id,
            "kind": self.kind,
            "status": "configured",
            "transport": "gateway_connector",
            "capabilities": [capability.value for capability in self.capabilities],
        }
