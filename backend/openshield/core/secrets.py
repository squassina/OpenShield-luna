import json
import os
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from openshield.core.storage import PostgresStore


class SecretConfigurationError(RuntimeError):
    pass


class SecretStore:
    """Encrypt integration secrets before they reach persistent storage."""

    def __init__(self, store: PostgresStore, key: str | None = None) -> None:
        configured_key = key if key is not None else os.getenv("OPENSHIELD_SECRET_KEY", "")
        if not configured_key:
            raise SecretConfigurationError("OPENSHIELD_SECRET_KEY is required to store integration credentials")
        try:
            self._cipher = Fernet(configured_key.encode("ascii"))
        except (ValueError, UnicodeEncodeError) as exc:
            raise SecretConfigurationError("OPENSHIELD_SECRET_KEY must be a valid Fernet key") from exc
        self._store = store

    def set(self, integration_id: str, value: dict[str, Any]) -> None:
        payload = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
        self._store.set_integration_secret(integration_id, self._cipher.encrypt(payload))

    def get(self, integration_id: str) -> dict[str, Any] | None:
        encrypted = self._store.get_integration_secret(integration_id)
        if encrypted is None:
            return None
        try:
            value = json.loads(self._cipher.decrypt(encrypted))
        except (InvalidToken, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SecretConfigurationError("Stored integration credentials cannot be decrypted; verify OPENSHIELD_SECRET_KEY") from exc
        if not isinstance(value, dict):
            raise SecretConfigurationError("Stored integration credentials have an invalid format")
        return value

    def delete(self, integration_id: str) -> bool:
        return self._store.delete_integration_secret(integration_id)
