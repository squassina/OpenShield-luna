import asyncio
import logging

from openshield.core.storage import PostgresStore
from openshield.integrations.registry import IntegrationRegistry
from openshield.response.engine import expire_due_actions

logger = logging.getLogger("openshield.response.worker")


async def run_response_expiry_loop(
    store: PostgresStore, registry: IntegrationRegistry, interval_seconds: int = 5,
) -> None:
    while True:
        try:
            result = await asyncio.to_thread(expire_due_actions, store, registry)
            if result["expired"] or result["rollback_pending"]:
                logger.info("Response TTL sweep completed", extra=result)
        except Exception:
            logger.exception("Response TTL sweep failed")
        await asyncio.sleep(interval_seconds)
