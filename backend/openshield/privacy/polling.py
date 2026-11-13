"""Background polling for configured DNS privacy providers."""
import asyncio
import logging
from datetime import UTC, datetime
from threading import Lock
from typing import Any

from openshield.privacy.dns import normalize_dns_batch
from openshield.privacy.providers import DnsProviderError, fetch_dns_records_page

logger = logging.getLogger(__name__)
DNS_PROVIDER_KINDS = {"pihole", "adguard"}
_STATUS_LOCK = Lock()
_POLL_STATUS: dict[str, dict[str, object]] = {}


def _record_poll_attempt(integration_id: str) -> None:
    with _STATUS_LOCK:
        previous = _POLL_STATUS.get(integration_id, {})
        _POLL_STATUS[integration_id] = {
            **previous, "status": "polling",
            "last_attempt_at": datetime.now(UTC).isoformat(),
        }


def _record_poll_success(integration_id: str, accepted: int, duplicates: int) -> None:
    now = datetime.now(UTC).isoformat()
    with _STATUS_LOCK:
        _POLL_STATUS[integration_id] = {
            **_POLL_STATUS.get(integration_id, {}),
            "status": "healthy", "last_attempt_at": now, "last_success_at": now,
            "last_imported": accepted, "last_duplicates": duplicates, "last_error": None,
        }


def _record_poll_failure(integration_id: str) -> None:
    with _STATUS_LOCK:
        _POLL_STATUS[integration_id] = {
            **_POLL_STATUS.get(integration_id, {}),
            "status": "failed", "last_attempt_at": datetime.now(UTC).isoformat(),
            "last_error": "Provider polling failed",
        }


def get_poll_status(integration_id: str) -> dict[str, object]:
    with _STATUS_LOCK:
        return dict(_POLL_STATUS.get(integration_id, {}))


def poll_dns_sources_once(registry: Any, store: Any, metrics: Any) -> list[dict[str, object]]:
    """Poll enabled DNS providers once; isolate failures so one source cannot block others."""
    outcomes = []
    for integration in registry.list_all():
        if integration.kind not in DNS_PROVIDER_KINDS or not integration.enabled:
            continue
        _record_poll_attempt(integration.integration_id)
        try:
            cursor = store.get_integration_poll_cursor(integration.integration_id)
            accepted = duplicates = received = pages = 0
            complete = False
            while pages < 10 and not complete:
                records, next_cursor, complete = fetch_dns_records_page(integration, cursor)
                events = normalize_dns_batch(integration.kind, integration.integration_id, records) if records else []
                for event in events:
                    if store.insert_event(event):
                        accepted += 1
                        metrics.increment("openshield_events_ingested_total")
                    else:
                        duplicates += 1
                received += len(events)
                store.set_integration_poll_cursor(integration.integration_id, integration.kind, next_cursor)
                cursor = next_cursor
                pages += 1
            _record_poll_success(integration.integration_id, accepted, duplicates)
            store.write_audit(
                "privacy.provider_poll.completed", None, integration.integration_id,
                {"provider": integration.kind, "received": received,
                 "accepted": accepted, "duplicates": duplicates, "pages": pages,
                 "complete": complete},
            )
            outcomes.append({"integration_id": integration.integration_id, "status": "ok",
                             "received": received, "accepted": accepted, "duplicates": duplicates,
                             "pages": pages, "complete": complete})
        except (DnsProviderError, ValueError, TypeError, OverflowError):
            logger.exception("DNS provider polling failed for integration %s", integration.integration_id)
            _record_poll_failure(integration.integration_id)
            store.write_audit(
                "privacy.provider_poll.failed", None, integration.integration_id,
                {"provider": integration.kind, "error": "provider_poll_failed"},
            )
            outcomes.append({"integration_id": integration.integration_id, "status": "error"})
    return outcomes


async def run_dns_polling_loop(registry: Any, store: Any, metrics: Any, interval_seconds: int) -> None:
    """Poll immediately on startup, then at a bounded configured interval."""
    while True:
        try:
            await asyncio.to_thread(poll_dns_sources_once, registry, store, metrics)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Unexpected error in DNS polling cycle")
        await asyncio.sleep(interval_seconds)
