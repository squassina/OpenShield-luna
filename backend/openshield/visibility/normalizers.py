from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from openshield.events.models import EventEnvelope, EventSource, Severity


SURICATA_FIELDS = (
    "src_ip", "src_port", "dest_ip", "dest_port", "proto", "app_proto",
    "community_id", "flow_id", "alert", "dns", "http", "tls", "flow",
)
ZEEK_FIELDS = (
    "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
    "service", "duration", "orig_bytes", "resp_bytes", "conn_state",
    "query", "qtype_name", "answers", "rcode_name", "method", "host",
    "uri", "status_code", "server_name", "version",
)


def _timestamp(value: Any) -> datetime:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, UTC)
    if isinstance(value, str):
        normalized = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
    raise ValueError("Sensor event requires a valid timestamp")


def _event_id(source: str, raw: dict[str, Any]) -> str:
    stable = raw.get("community_id") or raw.get("uid")
    if stable:
        return f"{source}:{str(stable)[:110]}"
    encoded = json.dumps(raw, sort_keys=True, separators=(",", ":"), default=str).encode()
    return f"{source}:{hashlib.sha256(encoded).hexdigest()}"


def normalize_suricata(raw: dict[str, Any], integration_id: str) -> EventEnvelope:
    """Normalize one Suricata EVE JSON record without retaining arbitrary fields."""
    event_type = raw.get("event_type")
    if event_type not in {"alert", "flow", "dns", "http", "tls", "ssh", "anomaly"}:
        raise ValueError("Unsupported Suricata EVE event_type")
    timestamp = _timestamp(raw.get("timestamp"))
    alert = raw.get("alert") if isinstance(raw.get("alert"), dict) else {}
    severity_value = alert.get("severity")
    severity = (
        Severity.HIGH if severity_value == 1 else
        Severity.MEDIUM if severity_value == 2 else
        Severity.LOW if severity_value == 3 else Severity.INFO
    )
    payload = {key: raw[key] for key in SURICATA_FIELDS if key in raw}
    if event_type == "alert" and isinstance(alert.get("signature"), str):
        payload["signature"] = alert["signature"][:256]
    return EventEnvelope(
        schema_version="openshield.event.v1",
        event_id=_event_id("suricata", raw),
        source=EventSource(integration_id=integration_id, kind="suricata"),
        event_type=f"network.suricata.{event_type}",
        occurred_at=timestamp,
        observed_at=datetime.now(UTC),
        severity=severity,
        payload=payload,
    )


def normalize_zeek(raw: dict[str, Any], integration_id: str) -> EventEnvelope:
    """Normalize one Zeek JSON log record; supports conn, dns, http and ssl logs."""
    log_type = raw.get("_path")
    if log_type not in {"conn", "dns", "http", "ssl"}:
        raise ValueError("Unsupported Zeek log type")
    timestamp = _timestamp(raw.get("ts"))
    payload = {key: raw[key] for key in ZEEK_FIELDS if key in raw}
    return EventEnvelope(
        schema_version="openshield.event.v1",
        event_id=_event_id(f"zeek-{log_type}", raw),
        source=EventSource(integration_id=integration_id, kind="zeek"),
        event_type=f"network.zeek.{log_type}",
        occurred_at=timestamp,
        observed_at=datetime.now(UTC),
        severity=Severity.INFO,
        payload=payload,
    )


def normalize_sensor_batch(
    kind: str, records: list[dict[str, Any]], integration_id: str
) -> list[EventEnvelope]:
    if not 1 <= len(records) <= 500:
        raise ValueError("Sensor batch must contain between 1 and 500 records")
    normalizer = {"suricata": normalize_suricata, "zeek": normalize_zeek}.get(kind)
    if normalizer is None:
        raise ValueError("Unsupported network sensor")
    return [normalizer(record, integration_id) for record in records]
