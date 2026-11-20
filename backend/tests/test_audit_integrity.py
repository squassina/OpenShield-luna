from datetime import UTC, datetime, timedelta, timezone

from openshield.core.audit_integrity import GENESIS_AUDIT_HASH, audit_record_hash


def test_audit_hash_is_deterministic_for_canonical_json_details() -> None:
    occurred_at = datetime(2026, 1, 2, 3, 4, 5, 123456, tzinfo=UTC)
    first = audit_record_hash(
        audit_id=7,
        occurred_at=occurred_at,
        actor_id="operator",
        action="integration.updated",
        target_id="router-lab",
        details={"config": {"enabled": True, "zones": ["lan", "wan"]}, "source": "ui"},
        previous_hash=GENESIS_AUDIT_HASH,
    )
    second = audit_record_hash(
        audit_id=7,
        occurred_at=occurred_at,
        actor_id="operator",
        action="integration.updated",
        target_id="router-lab",
        details={"source": "ui", "config": {"zones": ["lan", "wan"], "enabled": True}},
        previous_hash=GENESIS_AUDIT_HASH,
    )

    assert first == second
    assert len(first) == 64
    assert first == first.lower()


def test_audit_hash_normalizes_equivalent_timestamp_offsets() -> None:
    utc_time = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    offset_time = utc_time.astimezone(timezone(timedelta(hours=3)))
    details = {"status": "ok"}

    utc_hash = audit_record_hash(
        audit_id=1,
        occurred_at=utc_time,
        actor_id=None,
        action="gateway.connected",
        target_id="home-gateway",
        details=details,
        previous_hash=GENESIS_AUDIT_HASH,
    )
    offset_hash = audit_record_hash(
        audit_id=1,
        occurred_at=offset_time,
        actor_id=None,
        action="gateway.connected",
        target_id="home-gateway",
        details=details,
        previous_hash=GENESIS_AUDIT_HASH,
    )

    assert utc_hash == offset_hash


def test_audit_hash_changes_when_any_record_field_changes() -> None:
    occurred_at = datetime(2026, 1, 2, tzinfo=UTC)
    base = {
        "audit_id": 1,
        "occurred_at": occurred_at,
        "actor_id": None,
        "action": "event.ingested",
        "target_id": "router-lab",
        "details": {"event_id": "event-1"},
        "previous_hash": GENESIS_AUDIT_HASH,
    }
    baseline = audit_record_hash(**base)

    variants = [
        {**base, "audit_id": 2},
        {**base, "occurred_at": occurred_at.replace(second=1)},
        {**base, "actor_id": "operator"},
        {**base, "action": "event.deleted"},
        {**base, "target_id": "other-router"},
        {**base, "details": {"event_id": "event-2"}},
        {**base, "previous_hash": "a" * 64},
    ]
    assert all(audit_record_hash(**variant) != baseline for variant in variants)


def test_audit_hash_rejects_naive_timestamps_and_invalid_parent_hashes() -> None:
    try:
        audit_record_hash(
            audit_id=1,
            occurred_at=datetime(2026, 1, 2),
            actor_id=None,
            action="event.ingested",
            target_id=None,
            details={},
            previous_hash=GENESIS_AUDIT_HASH,
        )
    except ValueError as exc:
        assert "timezone-aware" in str(exc)
    else:
        raise AssertionError("Naive audit timestamp must be rejected")

    try:
        audit_record_hash(
            audit_id=1,
            occurred_at=datetime(2026, 1, 2, tzinfo=UTC),
            actor_id=None,
            action="event.ingested",
            target_id=None,
            details={},
            previous_hash="invalid",
        )
    except ValueError as exc:
        assert "SHA-256" in str(exc)
    else:
        raise AssertionError("Invalid previous hash must be rejected")
