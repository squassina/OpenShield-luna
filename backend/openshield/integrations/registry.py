from openshield.integrations import models

CAPABILITIES_BY_KIND: dict[str, list[models.Capability]] = {
    "openwrt": [
        models.Capability.HEALTH_CHECK,
        models.Capability.DISCOVER,
    ],
}


class IntegrationRegistry:
    """In-memory registry for the P0 API foundation; persistence is a follow-up."""

    def __init__(self) -> None:
        self._integrations: dict[str, models.Integration] = {}

    def register(
        self, registration: models.IntegrationRegistration
    ) -> models.Integration:
        if registration.integration_id in self._integrations:
            raise ValueError("Integration already exists")
        capabilities = CAPABILITIES_BY_KIND.get(registration.kind)
        if capabilities is None:
            raise ValueError("Unsupported integration kind")
        integration = models.Integration(
            **registration.model_dump(),
            capabilities=capabilities,
        )
        self._integrations[integration.integration_id] = integration
        return integration

    def get(self, integration_id: str) -> models.Integration | None:
        return self._integrations.get(integration_id)

    def list_all(self) -> list[models.Integration]:
        return list(self._integrations.values())
