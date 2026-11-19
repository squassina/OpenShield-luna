from urllib.parse import unquote, urlsplit


class DeploymentConfigurationError(RuntimeError):
    """Invalid or unsafe deployment configuration."""


_INSECURE_DATABASE_PASSWORDS = frozenset(
    {
        "openshield-dev-password",
        "replace-with-a-local-db-password",
        "password",
        "postgres",
        "changeme",
        "change-me",
    }
)
_PRODUCTION_DATABASE_MODES = {"production", "prod"}
_SUPPORTED_DEPLOYMENT_MODES = {"development", *_PRODUCTION_DATABASE_MODES}


def validate_deployment_database_credentials(
    deployment_mode: str,
    database_url: str,
    postgres_password: str,
) -> None:
    """Reject known development database credentials in production mode."""
    mode = deployment_mode.strip().lower()
    if mode not in _SUPPORTED_DEPLOYMENT_MODES:
        raise DeploymentConfigurationError(
            "OPENSHIELD_DEPLOYMENT_MODE must be 'development' or 'production'"
        )
    if mode not in _PRODUCTION_DATABASE_MODES:
        return

    if not postgres_password:
        raise DeploymentConfigurationError(
            "OPENSHIELD_POSTGRES_PASSWORD is required in production"
        )
    if len(postgres_password) < 16:
        raise DeploymentConfigurationError(
            "Production PostgreSQL passwords must contain at least 16 characters"
        )
    if postgres_password.casefold() in _INSECURE_DATABASE_PASSWORDS:
        raise DeploymentConfigurationError(
            "A known development/default PostgreSQL password cannot be used in production"
        )

    try:
        parsed = urlsplit(database_url)
        url_password = parsed.password
        # Accessing hostname may raise ValueError for malformed bracketed addresses.
        hostname = parsed.hostname
    except ValueError as exc:
        raise DeploymentConfigurationError(
            "OPENSHIELD_DATABASE_URL must be a valid PostgreSQL URL in production"
        ) from exc

    if (
        parsed.scheme not in {"postgres", "postgresql"}
        or not hostname
        or not parsed.username
        or url_password is None
    ):
        raise DeploymentConfigurationError(
            "OPENSHIELD_DATABASE_URL must include a PostgreSQL host, user and password in production"
        )

    if unquote(url_password) != postgres_password:
        raise DeploymentConfigurationError(
            "OPENSHIELD_POSTGRES_PASSWORD must match the password in OPENSHIELD_DATABASE_URL"
        )
