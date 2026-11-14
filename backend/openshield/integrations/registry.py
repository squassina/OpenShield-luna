from openshield.core.storage import PostgresStore
from openshield.integrations import models

CAPABILITIES_BY_KIND: dict[str, list[models.Capability]] = {
    "prometheus": [
        models.Capability.HEALTH_CHECK,
        models.Capability.READ_CONFIGURATION,
        models.Capability.READ_EVENTS,
    ],
    "opnsense": [
        models.Capability.HEALTH_CHECK,
        models.Capability.READ_CONFIGURATION,
        models.Capability.READ_EVENTS,
    ],
    "crowdsec": [models.Capability.HEALTH_CHECK, models.Capability.READ_EVENTS],
    "wazuh": [
        models.Capability.HEALTH_CHECK,
        models.Capability.READ_CONFIGURATION,
        models.Capability.READ_EVENTS,
    ],
    "pfsense": [
        models.Capability.HEALTH_CHECK,
        models.Capability.READ_CONFIGURATION,
        models.Capability.READ_EVENTS,
    ],
    "openwrt": [
        models.Capability.HEALTH_CHECK,
        models.Capability.DISCOVER,
    ],
    "suricata": [models.Capability.HEALTH_CHECK, models.Capability.READ_EVENTS],
    "zeek": [models.Capability.HEALTH_CHECK, models.Capability.READ_EVENTS],
    "pihole": [
        models.Capability.HEALTH_CHECK, models.Capability.READ_EVENTS,
        models.Capability.READ_CONFIGURATION, models.Capability.WRITE_CONFIGURATION,
    ],
    "adguard": [
        models.Capability.HEALTH_CHECK, models.Capability.READ_EVENTS,
        models.Capability.READ_CONFIGURATION, models.Capability.WRITE_CONFIGURATION,
    ],
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

    def update(
        self, integration_id: str, changes: models.IntegrationUpdate,
        actor_id: str | None = None,
    ) -> models.Integration | None:
        current = self.get(integration_id)
        if current is None:
            return None
        updated = models.Integration.model_validate({
            **current.model_dump(),
            **changes.model_dump(exclude_unset=True),
        })
        if self._store is not None:
            return self._store.update_integration(updated, actor_id)
        self._integrations[integration_id] = updated
        return updated

    def delete(self, integration_id: str, actor_id: str | None = None) -> bool:
        if self._store is not None:
            return self._store.delete_integration(integration_id, actor_id)
        return self._integrations.pop(integration_id, None) is not None

    def list_all(self) -> list[models.Integration]:
        if self._store is not None:
            return self._store.list_integrations()
        return list(self._integrations.values())
