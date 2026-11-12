from openshield.integrations.models import Capability, Integration


class NetworkSensorAdapter:
    """Capability descriptor for externally managed Suricata/Zeek sensors."""

    def __init__(self, kind: str) -> None:
        if kind not in {"suricata", "zeek"}:
            raise ValueError("Unsupported network sensor")
        self.kind = kind
        self.capabilities = [Capability.HEALTH_CHECK, Capability.READ_EVENTS]

    def probe(self, integration: Integration) -> dict[str, object]:
        return {
            "integration_id": integration.integration_id,
            "kind": self.kind,
            "status": "configured",
            "transport": "http_event_ingestion",
            "capabilities": [item.value for item in self.capabilities],
        }
