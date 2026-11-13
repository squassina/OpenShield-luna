"""Background polling for configured DNS privacy providers."""
import asyncio
import logging
from typing import Any

from openshield.privacy.dns import normalize_dns_batch
from openshield.privacy.providers import DnsProviderError, fetch_dns_records

logger = logging.getLogger(__name__)
DNS_PROVIDER_KINDS = {"pihole", "adguard"}


def poll_dns_sources_once(registry: Any, store: Any, metrics: Any) -> list[dict[str, object]]:
    """Poll enabled DNS providers once; isolate failures so one source cannot block others."""
    outcomes = []
    for integration in registry.list_all():
        if integration.kind not in DNS_PROVIDER_KINDS or not integration.enabled:
            continue
        try:
            records = fetch_dns_records(integration)
            events = normalize_dns_batch(integration.kind, integration.integration_id, records) if records else []
            accepted = duplicates = 0
            for event in events:
                if store.insert_event(event):
                    accepted += 1
                    metrics.increment("openshield_events_ingested_total")
                else:
                    duplicates += 1
            store.write_audit(
                "privacy.provider_poll.completed", None, integration.integration_id,
                {"provider": integration.kind, "received": len(events),
                 "accepted": accepted, "duplicates": duplicates},
            )
            outcomes.append({"integration_id": integration.integration_id, "status": "ok",
                             "received": len(events), "accepted": accepted, "duplicates": duplicates})
        except (DnsProviderError, ValueError, TypeError, OverflowError):
            logger.exception("DNS provider polling failed for integration %s", integration.integration_id)
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
