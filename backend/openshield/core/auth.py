import hashlib
import hmac
import json
import os
from collections.abc import Callable
from enum import StrEnum
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, ValidationError


class Role(StrEnum):
    ADMIN = "admin"
    OPERATOR = "operator"
    READER = "reader"
    GATEWAY = "gateway"


class Permission(StrEnum):
    INTEGRATIONS_READ = "integrations:read"
    INTEGRATIONS_WRITE = "integrations:write"
    EVENTS_READ = "events:read"
    EVENTS_WRITE = "events:write"
    GATEWAY_CONNECT = "gateway:connect"
    GATEWAY_HEARTBEAT = "gateway:heartbeat"
    GATEWAY_READ = "gateway:read"
    AUDIT_READ = "audit:read"


ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.ADMIN: frozenset(Permission),
    Role.OPERATOR: frozenset(
        {
            Permission.INTEGRATIONS_READ,
            Permission.EVENTS_READ,
            Permission.EVENTS_WRITE,
        }
    ),
    Role.READER: frozenset(
        {Permission.INTEGRATIONS_READ, Permission.EVENTS_READ}
    ),
    Role.GATEWAY: frozenset({Permission.EVENTS_WRITE, Permission.GATEWAY_CONNECT, Permission.GATEWAY_HEARTBEAT}),
}


class APIKeyRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key_id: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]{1,63}$")
    role: Role
    key_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class Principal(BaseModel):
    key_id: str
    role: Role


class AuthenticationConfigurationError(ValueError):
    pass


bearer_scheme = HTTPBearer(auto_error=False)


def _load_api_keys() -> list[APIKeyRecord]:
    raw_config = os.getenv("OPENSHIELD_API_KEYS", "").strip()
    if not raw_config:
        raise AuthenticationConfigurationError("API keys are not configured")

    try:
        payload = json.loads(raw_config)
        if not isinstance(payload, list) or not payload:
            raise ValueError("Expected a non-empty JSON array")
        records = [APIKeyRecord.model_validate(item) for item in payload]
    except (json.JSONDecodeError, TypeError, ValueError, ValidationError) as exc:
        raise AuthenticationConfigurationError("Invalid API key configuration") from exc

    key_ids = [record.key_id for record in records]
    key_hashes = [record.key_hash for record in records]
    if len(key_ids) != len(set(key_ids)) or len(key_hashes) != len(set(key_hashes)):
        raise AuthenticationConfigurationError("Duplicate API key identifiers or hashes")

    return records


def authentication_is_configured() -> bool:
    try:
        _load_api_keys()
    except AuthenticationConfigurationError:
        return False
    return True


def require_permissions(*permissions: Permission) -> Callable:
    required = frozenset(permissions)

    def dependency(
        credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    ) -> Principal:
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Bearer API key required",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if len(credentials.credentials) < 32:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
                headers={"WWW-Authenticate": "Bearer"},
            )

        try:
            records = _load_api_keys()
        except AuthenticationConfigurationError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="API authentication is not configured correctly",
            ) from exc

        supplied_hash = hashlib.sha256(credentials.credentials.encode("utf-8")).hexdigest()
        matched_record = None
        for record in records:
            if hmac.compare_digest(supplied_hash, record.key_hash):
                matched_record = record

        if matched_record is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
                headers={"WWW-Authenticate": "Bearer"},
            )

        granted = ROLE_PERMISSIONS[matched_record.role]
        if not required.issubset(granted):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )

        return Principal(key_id=matched_record.key_id, role=matched_record.role)

    return dependency
