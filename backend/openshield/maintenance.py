"""Explicit, bounded event-retention maintenance command."""
import os
from datetime import UTC, datetime, timedelta

from openshield.core.storage import PostgresStore

def run_retention() -> int:
    raw_days = os.getenv("OPENSHIELD_EVENT_RETENTION_DAYS", "0")
    try:
        days = int(raw_days)
    except ValueError as exc:
        raise SystemExit("OPENSHIELD_EVENT_RETENTION_DAYS must be an integer") from exc
    if days < 0:
        raise SystemExit("OPENSHIELD_EVENT_RETENTION_DAYS cannot be negative")
    if days == 0:
        print("Event retention disabled (OPENSHIELD_EVENT_RETENTION_DAYS=0).")
        return 0
    store = PostgresStore(os.getenv("OPENSHIELD_DATABASE_URL", ""))
    cutoff = datetime.now(UTC) - timedelta(days=days)
    deleted = 0
    while True:
        count = store.purge_events_before(cutoff, batch_size=1000)
        deleted += count
        if count < 1000:
            break
    print(f"Deleted {deleted} events received before {cutoff.isoformat()}.")
    return deleted

if __name__ == "__main__":
    run_retention()
