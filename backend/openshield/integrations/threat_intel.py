from openshield.integrations.models import Capability, Integration


class ThreatIntelAdapter:
    """Read-only adapter metadata for external reputation and IOC providers."""

    def __init__(self, kind: str) -> None:
        if kind not in {"crowdsec", "misp"}:
            raise ValueError("Unsupported threat intelligence integration")
        self.kind = kind

    def probe(self, integration: Integration) -> dict[str, object]:
        return {
            "integration_id": integration.integration_id,
            "kind": self.kind,
            "status": "configured",
            "transport": "outbound_https",
            "capabilities": [Capability.HEALTH_CHECK.value, Capability.READ_EVENTS.value],
            "credentials_configured": False,
        }
