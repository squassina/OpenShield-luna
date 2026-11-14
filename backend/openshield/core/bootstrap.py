import os
import secrets
from pathlib import Path

from cryptography.fernet import Fernet


def _read_or_create(path: Path, value: str | None, *, create: bool) -> str:
    if value:
        return value
    try:
        return path.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        if not create:
            raise RuntimeError(f"OpenShield runtime secret is missing: {path.name}")
    generated = Fernet.generate_key().decode("ascii") if path.name == "fernet.key" else secrets.token_urlsafe(48)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return path.read_text(encoding="ascii").strip()
    with os.fdopen(descriptor, "w", encoding="ascii") as secret_file:
        secret_file.write(generated)
        secret_file.write("\n")
        secret_file.flush()
        os.fsync(secret_file.fileno())
    return generated


def load_runtime_secrets(*, create: bool) -> None:
    """Load persistent Fernet and gateway keys shared by Node and its local connector.

    The Node creates missing keys in the persistent Docker volume. The connector
    only reads them. Explicit environment variables retain precedence for existing
    deployments and externally managed secrets.
    """
    directory = os.getenv("OPENSHIELD_RUNTIME_SECRETS_DIR", "").strip()
    if not directory:
        return
    root = Path(directory)
    if create:
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        root.chmod(0o700)
    elif not root.is_dir():
        raise RuntimeError("OpenShield runtime secrets volume is not mounted")

    values = {
        "OPENSHIELD_SECRET_KEY": root / "fernet.key",
        "OPENSHIELD_GATEWAY_TOKEN": root / "gateway.token",
    }
    for variable, path in values.items():
        value = _read_or_create(path, os.getenv(variable), create=create)
        if variable == "OPENSHIELD_SECRET_KEY":
            try:
                Fernet(value.encode("ascii"))
            except (ValueError, UnicodeEncodeError) as exc:
                raise RuntimeError("Persisted OpenShield encryption key is invalid") from exc
        os.environ[variable] = value
