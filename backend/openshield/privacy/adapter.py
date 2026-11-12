from openshield.integrations.models import Capability, Integration


class DnsPrivacyAdapter:
    """Read-only DNS telemetry adapter contract; records are pushed by provider exporters."""

    def __init__(self, kind: str) -> None:
        if kind not in {"pihole", "adguard"}:
            raise ValueError("Unsupported DNS privacy provider")
        self.kind = kind
        self.capabilities = [
            Capability.HEALTH_CHECK, Capability.READ_EVENTS,
            Capability.READ_CONFIGURATION, Capability.WRITE_CONFIGURATION,
        ]

    def probe(self, integration: Integration) -> dict[str, object]:
        return {
            "integration_id": integration.integration_id,
            "kind": self.kind,
            "status": "configured",
            "transport": "http_event_ingestion",
            "capabilities": [item.value for item in self.capabilities],
            "configuration": "provider credentials are not stored by OpenShield",
        }
