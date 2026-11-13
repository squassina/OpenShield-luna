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
            previous = [
                Fernet(item.strip().encode("ascii"))
                for item in os.getenv("OPENSHIELD_SECRET_KEY_PREVIOUS", "").split(",")
                if item.strip()
            ]
        except (ValueError, UnicodeEncodeError) as exc:
            raise SecretConfigurationError("Secret encryption keys must be valid Fernet keys") from exc
        self._previous_ciphers = previous
        self._store = store

    def set(self, integration_id: str, value: dict[str, Any]) -> None:
        payload = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
        self._store.set_integration_secret(integration_id, self._cipher.encrypt(payload))

    def get(self, integration_id: str) -> dict[str, Any] | None:
        encrypted = self._store.get_integration_secret(integration_id)
        if encrypted is None:
            return None
        decrypted = None
        used_previous_key = False
        for cipher in (self._cipher, *self._previous_ciphers):
            try:
                decrypted = cipher.decrypt(encrypted)
                used_previous_key = cipher is not self._cipher
                break
            except InvalidToken:
                continue
        if decrypted is None:
            raise SecretConfigurationError(
                "Stored integration credentials cannot be decrypted; verify the active and previous secret keys"
            )
        try:
            value = json.loads(decrypted)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SecretConfigurationError("Stored integration credentials have an invalid format") from exc
        if not isinstance(value, dict):
            raise SecretConfigurationError("Stored integration credentials have an invalid format")
        if used_previous_key:
            self.set(integration_id, value)
        return value

    def delete(self, integration_id: str) -> bool:
        return self._store.delete_integration_secret(integration_id)
