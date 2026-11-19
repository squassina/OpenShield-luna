import ipaddress
import os
from urllib.parse import unquote, urlsplit


class DeploymentConfigurationError(RuntimeError):
    """Raised when a deployment profile is missing mandatory security settings."""


def _enabled(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes"}


def validate_deployment_configuration(
    environ: dict[str, str] | None = None,
) -> None:
    """Fail closed for the production profile while preserving Home defaults."""
    values = os.environ if environ is None else environ
    profile = values.get("OPENSHIELD_DEPLOYMENT_PROFILE", "home").strip().lower()
    if profile not in {"home", "production"}:
        raise DeploymentConfigurationError(
            "OPENSHIELD_DEPLOYMENT_PROFILE must be 'home' or 'production'"
        )
    if profile == "home":
        return

    if not _enabled(values.get("OPENSHIELD_API_AUTH_ENABLED", "false")):
        raise DeploymentConfigurationError(
            "Production profile requires OPENSHIELD_API_AUTH_ENABLED=true"
        )
    username = values.get("OPENSHIELD_API_USERNAME", "").strip()
    api_password = values.get("OPENSHIELD_API_PASSWORD", "")
    if not username or len(api_password) < 20:
        raise DeploymentConfigurationError(
            "Production profile requires an admin username and a password of at least 20 characters"
        )

    postgres_password = values.get("OPENSHIELD_POSTGRES_PASSWORD", "")
    if len(postgres_password) < 24 or postgres_password.lower() in {
        "openshield-dev-password",
        "password",
        "changeme",
    } or "replace-with" in postgres_password.lower():
        raise DeploymentConfigurationError(
            "Production profile requires a unique PostgreSQL password of at least 24 characters"
        )

    database_url = values.get("OPENSHIELD_DATABASE_URL", "")
    try:
        parsed = urlsplit(database_url)
        url_password = unquote(parsed.password or "")
    except ValueError as exc:
        raise DeploymentConfigurationError(
            "Production profile requires a valid OPENSHIELD_DATABASE_URL"
        ) from exc
    if (
        parsed.scheme not in {"postgres", "postgresql"}
        or not parsed.hostname
        or not url_password
        or url_password != postgres_password
    ):
        raise DeploymentConfigurationError(
            "OPENSHIELD_DATABASE_URL credentials must match OPENSHIELD_POSTGRES_PASSWORD"
        )

    publish_address = values.get("OPENSHIELD_PUBLISH_ADDRESS", "127.0.0.1").strip()
    try:
        address = ipaddress.ip_address(publish_address)
    except ValueError as exc:
        raise DeploymentConfigurationError(
            "OPENSHIELD_PUBLISH_ADDRESS must be a specific IP address"
        ) from exc
    if address.is_unspecified or address.is_multicast:
        raise DeploymentConfigurationError(
            "Production profile cannot publish the Node API on an unspecified or multicast address"
        )
