import asyncio
import logging

from openshield.core.storage import PostgresStore
from openshield.execution.service import expire_due_executions
from openshield.integrations.registry import IntegrationRegistry

logger = logging.getLogger("openshield.execution.worker")


async def run_expiration_loop(
    store: PostgresStore, registry: IntegrationRegistry, interval_seconds: int = 15,
) -> None:
    while True:
        try:
            await asyncio.to_thread(expire_due_executions, store, registry)
        except Exception:
            logger.exception("Response execution expiry worker failed")
        await asyncio.sleep(interval_seconds)
