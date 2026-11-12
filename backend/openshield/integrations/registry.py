from openshield.core.storage import PostgresStore
from openshield.integrations import models

CAPABILITIES_BY_KIND: dict[str, list[models.Capability]] = {
    "openwrt": [
        models.Capability.HEALTH_CHECK,
        models.Capability.DISCOVER,
    ],
    "suricata": [models.Capability.HEALTH_CHECK, models.Capability.READ_EVENTS],
    "zeek": [models.Capability.HEALTH_CHECK, models.Capability.READ_EVENTS],
}


class IntegrationRegistry:
    """Integration registry backed by PostgreSQL when a store is supplied."""

    def __init__(self, store: PostgresStore | None = None) -> None:
        self._store = store
        self._integrations: dict[str, models.Integration] = {}

    def register(
        self, registration: models.IntegrationRegistration, actor_id: str | None = None
    ) -> models.Integration:
        capabilities = CAPABILITIES_BY_KIND.get(registration.kind)
        if capabilities is None:
            raise ValueError("Unsupported integration kind")
        integration = models.Integration(
            **registration.model_dump(),
            capabilities=capabilities,
        )
        if self._store is not None:
            self._store.insert_integration(integration, actor_id)
        else:
            if integration.integration_id in self._integrations:
                raise ValueError("Integration already exists")
            self._integrations[integration.integration_id] = integration
        return integration

    def get(self, integration_id: str) -> models.Integration | None:
        if self._store is not None:
            return self._store.get_integration(integration_id)
        return self._integrations.get(integration_id)

    def list_all(self) -> list[models.Integration]:
        if self._store is not None:
            return self._store.list_integrations()
        return list(self._integrations.values())
