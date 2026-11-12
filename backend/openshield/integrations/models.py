from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Capability(StrEnum):
    DISCOVER = "discover"
    HEALTH_CHECK = "health_check"
    READ_EVENTS = "read_events"
    READ_CONFIGURATION = "read_configuration"
    WRITE_CONFIGURATION = "write_configuration"
    EXECUTE_ACTION = "execute_action"
    VERIFY_ACTION = "verify_action"


class IntegrationRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    integration_id: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]{1,63}$")
    kind: str = Field(min_length=2, max_length=40)
    display_name: str = Field(min_length=1, max_length=120)
    config: dict[str, Any] = Field(default_factory=dict)

    @field_validator("config")
    @classmethod
    def reject_secret_material(cls, config: dict[str, Any]) -> dict[str, Any]:
        forbidden = ("password", "secret", "token", "credential", "private_key", "api_key")

        def validate(value: Any) -> None:
            if isinstance(value, dict):
                for key, nested in value.items():
                    normalized = str(key).lower().replace("-", "_")
                    if any(part in normalized for part in forbidden):
                        raise ValueError("Integration secrets must be supplied through secret environment variables")
                    validate(nested)
            elif isinstance(value, list):
                for nested in value:
                    validate(nested)

        validate(config)
        return config


class Integration(BaseModel):
    integration_id: str
    kind: str
    display_name: str
    capabilities: list[Capability]
    config: dict[str, Any]
    registered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
