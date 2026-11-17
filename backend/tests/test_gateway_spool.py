import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from openshield.events.models import EventEnvelope, EventSource, Severity
from openshield.gateway.spool import GatewayEventSpool


def _event(index: int) -> EventEnvelope:
    now = datetime.now(UTC)
    return EventEnvelope(
        schema_version="openshield.event.v1",
        event_id=f"discovery-{index}",
        source=EventSource(integration_id="gateway", kind="openwrt"),
        event_type="gateway.discovery",
        occurred_at=now,
        observed_at=now,
        severity=Severity.INFO,
        payload={"sequence": index},
    )


def test_enqueue_uses_transactional_counter_instead_of_counting_rows(
    tmp_path: Path, monkeypatch,
) -> None:
    spool = GatewayEventSpool(str(tmp_path / "counter.sqlite3"), max_events=4)
    statements: list[str] = []
    original_connection = spool._connection

    @contextmanager
    def traced_connection():
        with original_connection() as connection:
            connection.set_trace_callback(statements.append)
            yield connection

    monkeypatch.setattr(spool, "_connection", traced_connection)
    assert spool.enqueue(_event(1)) is True

    assert not any(
        "COUNT(*)" in statement.upper() and "PENDING_EVENTS" in statement.upper()
        for statement in statements
    )
    with sqlite3.connect(spool._path) as connection:
        count = connection.execute(
            "SELECT value FROM gateway_spool_counters WHERE name = 'pending_events'"
        ).fetchone()[0]
    assert count == 1


def test_spool_counter_stays_correct_across_acknowledgement_and_restart(
    tmp_path: Path,
) -> None:
    path = tmp_path / "restart-counter.sqlite3"
    spool = GatewayEventSpool(str(path), max_events=2)
    first, second = _event(1), _event(2)
    spool.enqueue(first)
    spool.enqueue(second)
    spool.acknowledge(first.event_id)
    assert spool.pending_count() == 1

    # Simulate stale metadata; startup reconciles it from the durable queue once.
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE gateway_spool_counters SET value = 0 WHERE name = 'pending_events'"
        )
        connection.commit()

    restarted = GatewayEventSpool(str(path), max_events=2)
    with sqlite3.connect(path) as connection:
        count = connection.execute(
            "SELECT value FROM gateway_spool_counters WHERE name = 'pending_events'"
        ).fetchone()[0]
    assert count == restarted.pending_count() == 1
    restarted.enqueue(_event(3))
    assert restarted.pending_count() == 2


def test_concurrent_enqueues_never_exceed_capacity_or_corrupt_counter(
    tmp_path: Path,
) -> None:
    path = tmp_path / "concurrent-counter.sqlite3"
    capacity = 12
    spools = [GatewayEventSpool(str(path), max_events=capacity) for _ in range(4)]

    def enqueue(index: int) -> None:
        spools[index % len(spools)].enqueue(_event(index))

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(enqueue, range(80)))

    assert spools[0].pending_count() == capacity
    with sqlite3.connect(path) as connection:
        count = connection.execute(
            "SELECT value FROM gateway_spool_counters WHERE name = 'pending_events'"
        ).fetchone()[0]
        stored = connection.execute("SELECT COUNT(*) FROM pending_events").fetchone()[0]
    assert count == stored == capacity
