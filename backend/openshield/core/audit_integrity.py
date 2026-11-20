from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

GENESIS_AUDIT_HASH = "0" * 64
AUDIT_HASH_VERSION = "openshield.audit.v1"


def audit_record_hash(
    *,
    audit_id: int,
    occurred_at: datetime,
    actor_id: str | None,
    action: str,
    target_id: str | None,
    details: dict[str, Any],
    previous_hash: str,
) -> str:
    """Return a deterministic SHA-256 hash for one canonical audit record."""
    if occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
        raise ValueError("Audit record timestamps must be timezone-aware")
    if len(previous_hash) != 64:
        raise ValueError("Previous audit hash must be a SHA-256 hex digest")

    canonical_record = {
        "version": AUDIT_HASH_VERSION,
        "audit_id": audit_id,
        "occurred_at": occurred_at.astimezone(UTC).isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z"),
        "actor_id": actor_id,
        "action": action,
        "target_id": target_id,
        "details": details,
        "previous_hash": previous_hash,
    }
    payload = json.dumps(
        canonical_record,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
