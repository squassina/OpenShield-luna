import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from rate_limit_helpers import reset_rate_limits

from openshield.api.main import app
from openshield.events.models import EventEnvelope, EventSource, Severity
from openshield.visibility.normalizers import (
    normalize_sensor_batch,
    normalize_suricata,
    normalize_zeek,
)

client = TestClient(app, headers={"Authorization": "Bearer connector-test-token"})
sensor_tokens: dict[str, str] = {}


def setup_function() -> None:
    os.environ["OPENSHIELD_GATEWAY_TOKEN"] = "connector-test-token"
    os.environ["OPENSHIELD_SECRET_KEY"] = Fernet.generate_key().decode()
    sensor_tokens.clear()
