"""Coordinate singleton background workers across Node processes and replicas."""

import asyncio
import logging

import psycopg

from openshield.execution.worker import run_expiration_loop
from openshield.privacy.polling import run_dns_polling_loop

logger = logging.getLogger(__name__)
_BACKGROUND_WORKER_LOCK_ID = 710_650_202_611_190_001
_RETRY_SECONDS = 5
_CHECK_SECONDS = 5
_CHECK_TIMEOUT_SECONDS = 10


async def _acquire_background_worker_lock(dsn: str) -> psycopg.AsyncConnection | None:
    if not dsn.strip():
        raise ValueError("OPENSHIELD_DATABASE_URL is required for worker coordination")
    connection = await psycopg.AsyncConnection.connect(
        dsn,
        autocommit=True,
        connect_timeout=5,
    )
    try:
        cursor = await connection.execute(
            "SELECT pg_try_advisory_lock(%s)",
            (_BACKGROUND_WORKER_LOCK_ID,),
        )
        acquired = (await cursor.fetchone())[0]
        if not acquired:
            await connection.close()
            return None
        return connection
    except Exception:
        await connection.close()
        raise


async def run_coordinated_background_workers(
    dsn: str,
    registry: object,
    store: object,
    metrics: object,
    dns_interval_seconds: int,
) -> None:
    """Run polling/expiry loops only while this process holds the DB session lock."""
    while True:
        connection: psycopg.AsyncConnection | None = None
        tasks: list[asyncio.Task[None]] = []
        try:
            connection = await _acquire_background_worker_lock(dsn)
            if connection is None:
                logger.info("Background workers are owned by another Node; retrying")
                await asyncio.sleep(_RETRY_SECONDS)
                continue

            logger.info("This Node owns the PostgreSQL background-worker lock")
            if dns_interval_seconds:
                tasks.append(asyncio.create_task(
                    run_dns_polling_loop(registry, store, metrics, dns_interval_seconds),
                ))
            tasks.append(asyncio.create_task(run_expiration_loop(store, registry)))

            while True:
                await asyncio.sleep(_CHECK_SECONDS)
                await asyncio.wait_for(
                    connection.execute("SELECT 1"),
                    timeout=_CHECK_TIMEOUT_SECONDS,
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception(
                "Background-worker lock unavailable or lost; workers will retry",
            )
            await asyncio.sleep(_RETRY_SECONDS)
        finally:
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            if connection is not None:
                try:
                    await connection.close()
                except Exception:
                    logger.warning("Failed to close background-worker lock connection")
