import sqlite3
from datetime import UTC, datetime

import pytest
from cryptography.fernet import Fernet

from openshield.events.models import EventEnvelope, EventSource, Severity
from openshield.gateway.spool import GatewayEventSpool, SpoolEncryptionError


def _event(event_id: str = "encrypted-event") -> EventEnvelope:
    now = datetime.now(UTC)
    return EventEnvelope(
        schema_version="openshield.event.v1",
        event_id=event_id,
        source=EventSource(integration_id="home-gateway", kind="openwrt"),
        event_type="gateway.discovery",
        occurred_at=now,
        observed_at=now,
        severity=Severity.INFO,
        payload={
            "client_ip": "192.168.1.42",
            "mac_address": "aa:bb:cc:dd:ee:ff",
            "hostname": "private-device",
        },
    )


def _stored_payload(path, table: str, column: str, key: str) -> str:
    with sqlite3.connect(path) as connection:
        return connection.execute(
            f"SELECT {column} FROM {table} WHERE {key} = ?",
            ("encrypted-event",),
        ).fetchone()[0]


def test_spool_encrypts_event_and_command_result_payloads_at_rest(tmp_path) -> None:
    path = tmp_path / "encrypted.sqlite3"
    key = Fernet.generate_key().decode("ascii")
    spool = GatewayEventSpool(str(path), encryption_key=key)

    assert spool.enqueue(_event()) is True
    spool.enqueue_command_result(
        "command-1", "completed", {"router_ip": "192.168.1.1", "hostname": "private-router"}
    )

    event_payload = _stored_payload(path, "pending_events", "payload", "encrypted-event")
    with sqlite3.connect(path) as connection:
        command_payload = connection.execute(
            "SELECT result FROM gateway_command_results WHERE command_id = ?",
            ("command-1",),
        ).fetchone()[0]

    assert event_payload.startswith("fernet:v1:")
    assert command_payload.startswith("fernet:v1:")
    assert "192.168.1.42" not in event_payload
    assert "private-device" not in event_payload
    assert "192.168.1.1" not in command_payload
    assert spool.pending() == [_event()]
    assert spool.get_command_result("command-1") == {
        "command_id": "command-1",
        "status": "completed",
        "result": {"router_ip": "192.168.1.1", "hostname": "private-router"},
        "acknowledged": False,
    }


def test_spool_migrates_legacy_plaintext_rows_on_first_encrypted_startup(tmp_path) -> None:
    path = tmp_path / "legacy.sqlite3"
    legacy = GatewayEventSpool(str(path))
    legacy.enqueue(_event())
    legacy.enqueue_command_result(
        "command-1", "completed", {"hostname": "private-router"}
    )

    key = Fernet.generate_key().decode("ascii")
    encrypted = GatewayEventSpool(str(path), encryption_key=key)

    event_payload = _stored_payload(path, "pending_events", "payload", "encrypted-event")
    with sqlite3.connect(path) as connection:
        command_payload = connection.execute(
            "SELECT result FROM gateway_command_results WHERE command_id = ?",
            ("command-1",),
        ).fetchone()[0]

    assert event_payload.startswith("fernet:v1:")
    assert command_payload.startswith("fernet:v1:")
    assert "192.168.1.42" not in event_payload
    assert "private-router" not in command_payload
    assert encrypted.pending() == [_event()]
    assert encrypted.get_command_result("command-1")["result"] == {
        "hostname": "private-router",
    }


def test_spool_rotation_reencrypts_old_rows_and_accepts_only_active_key_afterward(
    tmp_path,
) -> None:
    path = tmp_path / "rotate.sqlite3"
    old_key = Fernet.generate_key().decode("ascii")
    new_key = Fernet.generate_key().decode("ascii")
    old_spool = GatewayEventSpool(str(path), encryption_key=old_key)
    old_spool.enqueue(_event())

    rotated = GatewayEventSpool(
        str(path),
        encryption_key=new_key,
        previous_encryption_keys=old_key,
    )

    assert rotated.pending() == [_event()]
    payload = _stored_payload(path, "pending_events", "payload", "encrypted-event")
    plaintext = Fernet(new_key.encode("ascii")).decrypt(
        payload.removeprefix("fernet:v1:").encode("ascii")
    )
    assert b"192.168.1.42" in plaintext

    reopened = GatewayEventSpool(str(path), encryption_key=new_key)
    assert reopened.pending() == [_event()]


def test_spool_refuses_to_open_encrypted_data_with_wrong_key(tmp_path) -> None:
    path = tmp_path / "wrong-key.sqlite3"
    key = Fernet.generate_key().decode("ascii")
    wrong_key = Fernet.generate_key().decode("ascii")
    GatewayEventSpool(str(path), encryption_key=key).enqueue(_event())

    with pytest.raises(SpoolEncryptionError, match="cannot be decrypted"):
        GatewayEventSpool(str(path), encryption_key=wrong_key)


def test_spool_refuses_encrypted_data_when_key_is_missing(tmp_path) -> None:
    path = tmp_path / "missing-key.sqlite3"
    key = Fernet.generate_key().decode("ascii")
    GatewayEventSpool(str(path), encryption_key=key).enqueue(_event())

    with pytest.raises(SpoolEncryptionError, match="not configured"):
        GatewayEventSpool(str(path))
