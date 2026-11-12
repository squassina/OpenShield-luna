from openshield.integrations.models import Capability, Integration


class OpenWrtAdapter:
    """Read-only OpenWrt adapter boundary.

    Authenticated transport is intentionally deferred. This adapter never
    modifies firewall, routing, or forwarding configuration.
    """

    kind = "openwrt"
    capabilities = [
        Capability.HEALTH_CHECK,
        Capability.READ_EVENTS,
        Capability.DISCOVER,
    ]

    def probe(self, integration: Integration) -> dict[str, object]:
        return {
            "integration_id": integration.integration_id,
            "kind": self.kind,
            "status": "configured",
            "transport": "not_connected",
            "capabilities": [capability.value for capability in self.capabilities],
            "message": "Adapter registered; authenticated OpenWrt transport is pending.",
        }
