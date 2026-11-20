import pytest

from openshield.core.deployment import (
    DeploymentConfigurationError,
    validate_deployment_database_credentials,
)

_VALID_PASSWORD = "production-password-with-entropy-2026"
_VALID_URL = (
    "postgresql://openshield:production-password-with-entropy-2026"
    "@db.internal:5432/openshield"
)


def test_development_mode_keeps_local_fallback_compatible() -> None:
    validate_deployment_database_credentials(
        "development",
        "postgresql://openshield:openshield-dev-password@openshield-db:5432/openshield",
        "openshield-dev-password",
    )


def test_production_mode_accepts_matching_unique_credentials() -> None:
    validate_deployment_database_credentials("production", _VALID_URL, _VALID_PASSWORD)


@pytest.mark.parametrize("mode", ["Production", "PRODUCTION"])
def test_production_mode_is_case_insensitive(mode: str) -> None:
    validate_deployment_database_credentials(mode, _VALID_URL, _VALID_PASSWORD)


@pytest.mark.parametrize("mode", ["", "staging", "test", "prod"])
def test_unknown_deployment_modes_fail_closed(mode: str) -> None:
    with pytest.raises(DeploymentConfigurationError, match="OPENSHIELD_DEPLOYMENT_MODE"):
        validate_deployment_database_credentials(mode, _VALID_URL, _VALID_PASSWORD)


def test_production_mode_requires_explicit_database_password() -> None:
    with pytest.raises(DeploymentConfigurationError, match="required in production"):
        validate_deployment_database_credentials(
            "production",
            "postgresql://openshield@db.internal:5432/openshield",
            "",
        )


@pytest.mark.parametrize(
    "password",
    [
        "openshield-dev-password",
        "replace-with-a-local-db-password",
        "password",
        "postgres",
        "changeme",
        "change-me",
    ],
)
def test_production_mode_rejects_known_default_passwords(password: str) -> None:
    with pytest.raises(DeploymentConfigurationError, match="development/default"):
        validate_deployment_database_credentials(
            "production",
            f"postgresql://openshield:{password}@db.internal:5432/openshield",
            password,
        )


def test_production_mode_rejects_passwords_with_outer_whitespace() -> None:
    password = f" {_VALID_PASSWORD}"
    database_url = (
        "postgresql://openshield:%20production-password-with-entropy-2026"
        "@db.internal:5432/openshield"
    )
    with pytest.raises(DeploymentConfigurationError, match="whitespace"):
        validate_deployment_database_credentials("production", database_url, password)


def test_production_mode_requires_at_least_16_password_characters() -> None:
    password = "short-secret"
    with pytest.raises(DeploymentConfigurationError, match="at least 16"):
        validate_deployment_database_credentials(
            "production",
            f"postgresql://openshield:{password}@db.internal:5432/openshield",
            password,
        )


def test_production_mode_requires_database_url_password_to_match() -> None:
    with pytest.raises(DeploymentConfigurationError, match="must match"):
        validate_deployment_database_credentials(
            "production",
            "postgresql://openshield:different-password@db.internal:5432/openshield",
            _VALID_PASSWORD,
        )


@pytest.mark.parametrize(
    "database_url",
    [
        "",
        "postgresql://openshield@db.internal:5432/openshield",
        "https://openshield:secret@db.internal/openshield",
        "postgresql://openshield:secret@/openshield",
        "postgresql://openshield:secret@[invalid]/openshield",
    ],
)
def test_production_mode_rejects_invalid_database_urls(database_url: str) -> None:
    with pytest.raises(DeploymentConfigurationError, match="OPENSHIELD_DATABASE_URL"):
        validate_deployment_database_credentials(
            "production",
            database_url,
            _VALID_PASSWORD,
        )


def test_production_mode_accepts_percent_encoded_url_password() -> None:
    password = "production+password/with@reserved-2026"
    database_url = (
        "postgresql://openshield:production%2Bpassword%2Fwith%40reserved-2026"
        "@db.internal:5432/openshield"
    )
    validate_deployment_database_credentials("production", database_url, password)
