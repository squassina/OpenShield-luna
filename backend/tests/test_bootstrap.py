import os
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from openshield.core.bootstrap import load_runtime_secrets


def test_runtime_secrets_are_generated_once_and_reused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENSHIELD_RUNTIME_SECRETS_DIR", str(tmp_path / "secrets"))
    monkeypatch.setenv("OPENSHIELD_SECRET_KEY", "")
    monkeypatch.setenv("OPENSHIELD_GATEWAY_TOKEN", "")

    load_runtime_secrets(create=True)
    encryption_key = os.environ["OPENSHIELD_SECRET_KEY"]
    gateway_token = os.environ["OPENSHIELD_GATEWAY_TOKEN"]
    Fernet(encryption_key.encode("ascii"))
    assert len(gateway_token) >= 64
    assert (tmp_path / "secrets" / "fernet.key").stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "secrets" / "gateway.token").stat().st_mode & 0o777 == 0o600

    monkeypatch.delenv("OPENSHIELD_SECRET_KEY")
    monkeypatch.delenv("OPENSHIELD_GATEWAY_TOKEN")
    load_runtime_secrets(create=False)
    assert os.environ["OPENSHIELD_SECRET_KEY"] == encryption_key
    assert os.environ["OPENSHIELD_GATEWAY_TOKEN"] == gateway_token


def test_connector_does_not_generate_missing_runtime_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENSHIELD_RUNTIME_SECRETS_DIR", str(tmp_path / "secrets"))
    with pytest.raises(RuntimeError, match="not mounted"):
        load_runtime_secrets(create=False)
    assert not (tmp_path / "secrets").exists()


def test_connector_can_load_gateway_token_without_encryption_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "secrets"
    root.mkdir()
    (root / "gateway.token").write_text("shared-token\n", encoding="ascii")
    monkeypatch.setenv("OPENSHIELD_RUNTIME_SECRETS_DIR", str(root))
    monkeypatch.delenv("OPENSHIELD_SECRET_KEY", raising=False)
    monkeypatch.delenv("OPENSHIELD_GATEWAY_TOKEN", raising=False)

    load_runtime_secrets(create=False, include_encryption=False)

    assert os.environ["OPENSHIELD_GATEWAY_TOKEN"] == "shared-token"
    assert "OPENSHIELD_SECRET_KEY" not in os.environ
