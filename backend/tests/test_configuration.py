import pytest

from openshield.core.configuration import (
    DeploymentConfigurationError,
    validate_deployment_configuration,
)


def _production_environment() -> dict[str, str]:
    password = "postgres-credential-that-is-long-enough"
    return {
        "OPENSHIELD_DEPLOYMENT_PROFILE": "production",
        "OPENSHIELD_API_AUTH_ENABLED": "true",
        "OPENSHIELD_API_USERNAME": "admin",
        "OPENSHIELD_API_PASSWORD": "a-strong-admin-password-with-24-chars",
        "OPENSHIELD_POSTGRES_PASSWORD": password,
        "OPENSHIELD_DATABASE_URL": (
            "postgresql://openshield:" + password + "@openshield-db:5432/openshield"
        ),
        "OPENSHIELD_PUBLISH_ADDRESS": "127.0.0.1",
    }


def test_home_profile_keeps_residential_defaults() -> None:
    validate_deployment_configuration({"OPENSHIELD_DEPLOYMENT_PROFILE": "home"})


def test_unset_profile_defaults_to_home() -> None:
    validate_deployment_configuration({})


def test_production_profile_accepts_explicit_strong_configuration() -> None:
    validate_deployment_configuration(_production_environment())


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        ("OPENSHIELD_API_AUTH_ENABLED", "false", "API_AUTH_ENABLED"),
        ("OPENSHIELD_API_PASSWORD", "short", "password of at least 20"),
        ("OPENSHIELD_POSTGRES_PASSWORD", "openshield-dev-password", "PostgreSQL password"),
        ("OPENSHIELD_DATABASE_URL", "postgresql://openshield:wrong@db/openshield", "must match"),
        ("OPENSHIELD_PUBLISH_ADDRESS", "0.0.0.0", "unspecified or multicast"),
    ],
)
def test_production_profile_rejects_unsafe_configuration(
    key: str, value: str, message: str,
) -> None:
    environment = _production_environment()
    environment[key] = value
    with pytest.raises(DeploymentConfigurationError, match=message):
        validate_deployment_configuration(environment)


def test_production_profile_rejects_invalid_profile() -> None:
    with pytest.raises(DeploymentConfigurationError, match="must be"):
        validate_deployment_configuration({"OPENSHIELD_DEPLOYMENT_PROFILE": "enterprise"})
