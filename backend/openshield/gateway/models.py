from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from openshield.integrations.models import Capability


class GatewayConnectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    protocol_version: Literal["openshield.gateway.v1"]
    gateway_id: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]{1,63}$")
    gateway_type: Literal["openwrt"]
    connector_version: str = Field(min_length=1, max_length=40)
    capabilities: list[Capability] = Field(max_length=16)

    @field_validator("capabilities")
    @classmethod
    def validate_capabilities(cls, values: list[Capability]) -> list[Capability]:
        allowed = {
            Capability.DISCOVER, Capability.HEALTH_CHECK, Capability.READ_EVENTS,
            Capability.EXECUTE_ACTION, Capability.VERIFY_ACTION,
        }
        if len(values) != len(set(values)) or not set(values).issubset(allowed):
            raise ValueError("Gateway advertised unsupported or duplicate capabilities")
        return values


class GatewayHeartbeatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    protocol_version: Literal["openshield.gateway.v1"]
    gateway_id: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]{1,63}$")


class GatewayConnection(BaseModel):
    gateway_id: str
    gateway_type: str
    connector_version: str
    protocol_version: str
    capabilities: list[Capability]
    connected_at: datetime
    last_seen_at: datetime

    @classmethod
    def create(cls, request: GatewayConnectRequest) -> "GatewayConnection":
        now = datetime.now(UTC)
        return cls(
            gateway_id=request.gateway_id,
            gateway_type=request.gateway_type,
            connector_version=request.connector_version,
            protocol_version=request.protocol_version,
            capabilities=request.capabilities,
            connected_at=now,
            last_seen_at=now,
        )
