from openshield.integrations.models import Capability, Integration


class AIProviderAdapter:
    """Read-only capability metadata for local and optional cloud AI providers."""

    def __init__(self, kind: str) -> None:
        if kind not in {"ollama", "openai"}:
            raise ValueError("Unsupported AI provider")
        self.kind = kind

    def probe(self, integration: Integration) -> dict[str, object]:
        return {
            "integration_id": integration.integration_id,
            "kind": self.kind,
            "status": "configured",
            "capabilities": [Capability.HEALTH_CHECK.value],
            "credentials_configured": self.kind == "ollama",
            "cloud_enabled": integration.config.get("cloud_enabled") is True,
        }
