"""Background polling for configured DNS privacy providers."""
import asyncio
import logging
from datetime import UTC, datetime
from threading import Lock
from typing import Any

import psycopg

from openshield.core.secrets import SecretConfigurationError, SecretStore
from openshield.privacy.dns import normalize_dns_batch_resilient
from openshield.privacy.providers import (
    DnsProviderCursorExpired,
    DnsProviderError,
    fetch_dns_records_page,
)

logger = logging.getLogger(__name__)
DNS_PROVIDER_KINDS = {"pihole", "adguard"}
MAX_PAGES_PER_POLL = 1
_STATUS_LOCK = Lock()
_POLL_STATUS: dict[str, dict[str, object]] = {}

_FAILURES = {
    "credential_error": ("DNS provider credentials could not be loaded", False),
    "provider_error": ("DNS provider request failed", True),
    "normalization_error": ("DNS provider response could not be normalized", False),
    "unexpected_error": ("Unexpected DNS polling error", True),
    "cursor_expired": ("Provider query-log cursor expired; reset required", False),
    "database_error": ("Database persistence failed; polling cycle aborted", True),
}


class PollingDatabaseError(RuntimeError):
    """A persistence failure that must abort the current polling cycle."""


class DnsNormalizationError(ValueError):
    """A provider page failed record-batch normalization."""


def _record_poll_attempt(integration_id: str) -> None:
    with _STATUS_LOCK:
        previous = _POLL_STATUS.get(integration_id, {})
        _POLL_STATUS[integration_id] = {
            **previous,
            "status": "polling",
            "last_attempt_at": datetime.now(UTC).isoformat(),
        }


def _record_poll_success(
    integration_id: str, accepted: int, duplicates: int, rejected: int = 0,
) -> None:
    now = datetime.now(UTC).isoformat()
    with _STATUS_LOCK:
        _POLL_STATUS[integration_id] = {
            **_POLL_STATUS.get(integration_id, {}),
            "status": "healthy",
            "last_attempt_at": now,
            "last_success_at": now,
            "last_imported": accepted,
            "last_duplicates": duplicates,
            "last_rejected": rejected,
            "last_error": None,
            "last_error_category": None,
            "retryable": None,
        }


def _record_poll_failure(
    integration_id: str, category: str, message: str, retryable: bool,
) -> None:
    now = datetime.now(UTC).isoformat()
    with _STATUS_LOCK:
        _POLL_STATUS[integration_id] = {
            **_POLL_STATUS.get(integration_id, {}),
            "status": "failed",
            "last_attempt_at": now,
            "last_failure_at": now,
            "last_error": message,
            "last_error_category": category,
            "retryable": retryable,
        }


def _metric(
    metrics: Any, name: str, labels: dict[str, str] | None = None,
) -> None:
    try:
        metrics.increment(name, labels)
    except Exception as exc:  # Metrics must not change polling or cursor semantics.
        logger.warning(
            "DNS polling metric update failed metric=%s error_type=%s",
            name, type(exc).__name__,
        )


def _base_labels(integration: Any) -> dict[str, str]:
    return {
        "integration_id": integration.integration_id,
        "provider": integration.kind,
    }


def _record_failure(
    integration: Any,
    store: Any,
    metrics: Any,
    category: str,
    *,
    audit_action: str = "privacy.provider_poll.failed",
) -> None:
    message, retryable = _FAILURES[category]
    integration_id = integration.integration_id
    _record_poll_failure(integration_id, category, message, retryable)
    labels = _base_labels(integration)
    _metric(metrics, "openshield_dns_poll_failures_total", {
        **labels, "category": category,
    })
    try:
        store.write_audit(
            audit_action, None, integration_id,
            {
                "provider": integration.kind,
                "category": category,
                "retryable": retryable,
            },
        )
    except psycopg.Error as exc:
        database_message, database_retryable = _FAILURES["database_error"]
        _record_poll_failure(
            integration_id, "database_error", database_message, database_retryable,
        )
        _metric(metrics, "openshield_dns_poll_failures_total", {
            **labels, "category": "database_error",
        })
        raise PollingDatabaseError(database_message) from exc


def reset_poll_status(integration_id: str) -> None:
    with _STATUS_LOCK:
        _POLL_STATUS.pop(integration_id, None)


def get_poll_status(integration_id: str) -> dict[str, object]:
    with _STATUS_LOCK:
        return dict(_POLL_STATUS.get(integration_id, {}))


def poll_dns_sources_once(registry: Any, store: Any, metrics: Any) -> list[dict[str, object]]:
    """Poll enabled DNS providers; isolate source errors and abort on database outages."""
    outcomes: list[dict[str, object]] = []
    for integration in registry.list_all():
        if integration.kind not in DNS_PROVIDER_KINDS or not integration.enabled:
            continue

        integration_id = integration.integration_id
        labels = _base_labels(integration)
        _record_poll_attempt(integration_id)
        _metric(metrics, "openshield_dns_poll_attempts_total", labels)

        try:
            encrypted = store.get_integration_secret(integration_id)
            credentials = SecretStore(store).get(integration_id) if encrypted else None
            cursor = store.get_integration_poll_cursor(integration_id)
            records, next_cursor, complete = fetch_dns_records_page(
                integration, cursor, credentials=credentials,
            ) if credentials is not None else fetch_dns_records_page(integration, cursor)

            try:
                events, rejections = normalize_dns_batch_resilient(
                    integration.kind,
                    integration_id,
                    records,
                    store.list_privacy_classification_overrides(),
                ) if records else ([], [])
            except (TypeError, ValueError, OverflowError, OSError) as exc:
                raise DnsNormalizationError(
                    "DNS provider page normalization failed"
                ) from exc

            accepted = duplicates = 0
            for event in events:
                if store.insert_event(event):
                    accepted += 1
                    _metric(metrics, "openshield_events_ingested_total")
                else:
                    duplicates += 1

            rejection_reasons: dict[str, int] = {}
            for rejection in rejections:
                reason = str(rejection["reason"])
                rejection_reasons[reason] = rejection_reasons.get(reason, 0) + 1

            rejection_details = None
            if rejections:
                rejection_details = {
                    "provider": integration.kind,
                    "count": len(rejections),
                    "reasons": rejection_reasons,
                    "record_indexes": [
                        int(item["record_index"]) for item in rejections[:20]
                    ],
                    "record_indexes_truncated": len(rejections) > 20,
                }

            completion_details = {
                "provider": integration.kind,
                "received": len(records),
                "accepted": accepted,
                "duplicates": duplicates,
                "rejected": len(rejections),
                "rejection_reasons": rejection_reasons,
                "pages": 1,
                "complete": complete,
            }
            # Cursor and audit records commit together. Inserted events are idempotent,
            # so a failed checkpoint safely replays the page without losing records.
            store.checkpoint_integration_poll_page(
                integration_id,
                integration.kind,
                next_cursor,
                completion_details,
                rejection_details,
            )

            rejected = len(rejections)
            _record_poll_success(integration_id, accepted, duplicates, rejected)
            _metric(metrics, "openshield_dns_poll_success_total", labels)
            for outcome, count in (
                ("accepted", accepted),
                ("duplicate", duplicates),
                ("rejected", rejected),
            ):
                if count:
                    _metric(metrics, "openshield_dns_poll_records_total", {
                        **labels, "outcome": outcome,
                    })
            if rejected:
                _metric(metrics, "openshield_dns_records_rejected_total")
            outcomes.append({
                "integration_id": integration_id,
                "status": "ok",
                "received": len(records),
                "accepted": accepted,
                "duplicates": duplicates,
                "rejected": rejected,
                "pages": 1,
                "complete": complete,
            })
        except psycopg.Error as exc:
            message, retryable = _FAILURES["database_error"]
            _record_poll_failure(integration_id, "database_error", message, retryable)
            _metric(metrics, "openshield_dns_poll_failures_total", {
                **labels, "category": "database_error",
            })
            logger.error(
                "DNS polling cycle aborted integration_id=%s category=database_error error_type=%s",
                integration_id, type(exc).__name__,
            )
            raise PollingDatabaseError(message) from exc
        except DnsProviderCursorExpired:
            logger.warning("DNS provider cursor expired integration_id=%s", integration_id)
            _record_failure(
                integration, store, metrics, "cursor_expired",
                audit_action="privacy.provider_poll.cursor_expired",
            )
            outcomes.append({
                "integration_id": integration_id,
                "status": "cursor_expired",
                "category": "cursor_expired",
            })
        except SecretConfigurationError:
            logger.error("DNS provider credentials unavailable integration_id=%s", integration_id)
            _record_failure(integration, store, metrics, "credential_error")
            outcomes.append({
                "integration_id": integration_id,
                "status": "error",
                "category": "credential_error",
            })
        except DnsProviderError:
            logger.error("DNS provider request failed integration_id=%s", integration_id)
            _record_failure(integration, store, metrics, "provider_error")
            outcomes.append({
                "integration_id": integration_id,
                "status": "error",
                "category": "provider_error",
            })
        except DnsNormalizationError:
            logger.error("DNS provider response normalization failed integration_id=%s", integration_id)
            _record_failure(integration, store, metrics, "normalization_error")
            outcomes.append({
                "integration_id": integration_id,
                "status": "error",
                "category": "normalization_error",
            })
        except Exception as exc:
            logger.error(
                "DNS polling failed integration_id=%s category=unexpected_error error_type=%s",
                integration_id, type(exc).__name__,
            )
            _record_failure(integration, store, metrics, "unexpected_error")
            outcomes.append({
                "integration_id": integration_id,
                "status": "error",
                "category": "unexpected_error",
            })
    return outcomes


async def run_dns_polling_loop(registry: Any, store: Any, metrics: Any, interval_seconds: int) -> None:
    """Poll immediately on startup, then at a bounded configured interval."""
    while True:
        try:
            await asyncio.to_thread(poll_dns_sources_once, registry, store, metrics)
        except asyncio.CancelledError:
            raise
        except PollingDatabaseError:
            logger.error("DNS polling cycle aborted after a database persistence failure")
        except Exception as exc:
            logger.error(
                "Unexpected DNS polling cycle failure error_type=%s",
                type(exc).__name__,
            )
        await asyncio.sleep(interval_seconds)
