from typing import Literal

from pydantic import BaseModel, Field


class ResponsePolicyRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    provider_integration_id: str = Field(min_length=2, max_length=64)
    action_type: Literal["dns_block_domain"] = "dns_block_domain"
    min_risk_score: int = Field(default=60, ge=0, le=100)
    ttl_seconds: int = Field(default=3600, ge=60, le=604800)
    approval_required: bool = True
    enabled: bool = True


class ResponsePolicyUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    min_risk_score: int | None = Field(default=None, ge=0, le=100)
    ttl_seconds: int | None = Field(default=None, ge=60, le=604800)
    approval_required: bool | None = None
    enabled: bool | None = None


class KillSwitchRequest(BaseModel):
    enabled: bool
    reason: str = Field(default="", max_length=500)
