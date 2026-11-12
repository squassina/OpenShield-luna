from openshield.integrations.models import Capability, Integration, IntegrationRegistration


CAPABILITIES_BY_KIND: dict[str, list[Capability]] = {
    "openwrt": [Capability.HEALTH_CHECK, Capability.READ_EVENTS, Capability.DISCOVER],
}


class IntegrationRegistry:
    """In-memory registry for the P0 API foundation; persistence is a follow-up."""

    def __init__(self) -> None:
        self._integrations: dict[str, Integration] = {}

    def register(self, registration: IntegrationRegistration) -> Integration:
        if registration.integration_id in self._integrations:
            raise ValueError("Integration already exists")
        capabilities = CAPABILITIES_BY_KIND.get(registration.kind)
        if capabilities is None:
            raise ValueError("Unsupported integration kind")
        integration = Integration(
            **registration.model_dump(),
            capabilities=capabilities,
        )
        self._integrations[integration.integration_id] = integration
        return integration

    def get(self, integration_id: str) -> Integration | None:
        return self._integrations.get(integration_id)

    def list_all(self) -> list[Integration]:
        return list(self._integrations.values())
