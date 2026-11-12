from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventSource(BaseModel):
    model_config = ConfigDict(extra="forbid")

    integration_id: str = Field(min_length=2, max_length=64)
    kind: str = Field(min_length=2, max_length=40)


class EventEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(pattern=r"^openshield\.event\.v1$")
    event_id: str = Field(min_length=1, max_length=128)
    source: EventSource
    event_type: str = Field(min_length=3, max_length=120)
    occurred_at: datetime
    observed_at: datetime
    severity: Severity
    payload: dict[str, Any]
