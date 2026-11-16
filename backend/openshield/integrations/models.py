import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from openshield.core.tls import resolve_ca_bundle_path


DEFAULT_FIREWALL_ZONES = {
    "source": {"src": "wan", "dest": "lan"},
    "destination": {"src": "lan", "dest": "wan"},
}


def validate_firewall_zones(value: Any) -> dict[str, dict[str, str]]:
    """Validate explicit UCI source/destination zone pairs for firewall actions."""
    if not isinstance(value, dict) or set(value) != {"source", "destination"}:
        raise ValueError("Firewall zones must define source and destination mappings")

    result: dict[str, dict[str, str]] = {}
    for direction in ("source", "destination"):
        pair = value[direction]
        if not isinstance(pair, dict) or set(pair) != {"src", "dest"}:
            raise ValueError("Each firewall direction must define src and dest zones")
        source = pair["src"]
        destination = pair["dest"]
        if not all(
            isinstance(zone, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,32}", zone)
            for zone in (source, destination)
        ):
            raise ValueError("Firewall zone names must contain only letters, numbers, '_' or '-'")
        if source == destination:
            raise ValueError("Firewall source and destination zones must be different")
        result[direction] = {"src": source, "dest": destination}
    return result


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
        if "firewall_zones" in config:
            config["firewall_zones"] = validate_firewall_zones(config["firewall_zones"])
        ca_bundle_path = config.get("ca_bundle_path")
        if ca_bundle_path not in (None, ""):
            resolved_ca_bundle = resolve_ca_bundle_path(ca_bundle_path)
            config["ca_bundle_path"] = str(resolved_ca_bundle)

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
    enabled: bool = True
    registered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class IntegrationUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    display_name: str | None = Field(default=None, min_length=1, max_length=120)
    config: dict[str, Any] | None = None
    enabled: bool | None = None

    @field_validator("config")
    @classmethod
    def reject_secret_material(cls, config: dict[str, Any] | None) -> dict[str, Any] | None:
        if config is not None:
            return IntegrationRegistration.reject_secret_material(config)
        return config
