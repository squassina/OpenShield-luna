import hashlib
import os

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from rate_limit_helpers import reset_rate_limits

from openshield.api.main import app
from openshield.core.secrets import SecretStore

client = TestClient(app)


def setup_function() -> None:
    os.environ["OPENSHIELD_SECRET_KEY"] = Fernet.generate_key().decode()
    os.environ["OPENSHIELD_API_AUTH_ENABLED"] = "false"
    from openshield.api import main

    reset_rate_limits(app)
    main.store.reset()
