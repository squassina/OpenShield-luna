from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr


class PiHoleCredentials(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: SecretStr = Field(min_length=1, max_length=1024)


class AdGuardCredentials(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: SecretStr = Field(min_length=1, max_length=256)
    password: SecretStr = Field(min_length=1, max_length=1024)


class OPNsenseCredentials(BaseModel):
    base_url: str = Field(min_length=8, max_length=500)
    api_key: str = Field(min_length=1, max_length=512)
    api_secret: SecretStr = Field(min_length=1, max_length=1024)


class PfSenseCredentials(BaseModel):
    base_url: str = Field(min_length=8, max_length=500)
    api_key: SecretStr = Field(min_length=1, max_length=1024)


class CrowdSecCredentials(BaseModel):
    base_url: str = Field(min_length=8, max_length=500)
    bouncer_api_key: SecretStr = Field(min_length=1, max_length=1024)
    machine_id: str | None = Field(default=None, max_length=128)
    machine_password: SecretStr | None = Field(default=None, max_length=1024)


class MispCredentials(BaseModel):
    base_url: str = Field(min_length=8, max_length=500)
    api_key: SecretStr = Field(min_length=1, max_length=1024)


class WazuhCredentials(BaseModel):
    base_url: str = Field(min_length=8, max_length=500)
    username: SecretStr = Field(min_length=1, max_length=256)
    password: SecretStr = Field(min_length=1, max_length=1024)


class PrometheusCredentials(BaseModel):
    base_url: str = Field(min_length=8, max_length=500)
    bearer_token: SecretStr | None = Field(default=None, min_length=1, max_length=4096)


class GrafanaCredentials(BaseModel):
    base_url: str = Field(min_length=8, max_length=500)
    bearer_token: SecretStr | None = Field(default=None, min_length=1, max_length=4096)


class OpenWrtCredentials(BaseModel):
    base_url: str = Field(min_length=8, max_length=500)
    username: str = Field(min_length=1, max_length=128)
    password: SecretStr = Field(min_length=1, max_length=512)


class ThreatIntelCredentials(BaseModel):
    api_key: SecretStr = Field(min_length=8, max_length=2048)


class AIProviderCredentials(BaseModel):
    api_key: SecretStr = Field(min_length=8, max_length=2048)


class AIInvestigationRequest(BaseModel):
    provider_id: str = Field(min_length=2, max_length=64)


class IncidentStatusRequest(BaseModel):
    status: Literal["open", "acknowledged", "closed", "false_positive"]
    reason: str = Field(default="", max_length=500)
