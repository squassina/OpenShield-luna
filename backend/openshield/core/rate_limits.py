from __future__ import annotations

import json
import math
import re
import threading
import time
from collections.abc import Awaitable, Callable
from typing import Any

_INGESTION_PATH = re.compile(
    r"/api/v1/(?:events|sensors/[^/]+/events|dns/[^/]+/queries)/?"
)
_SENSOR_CREDENTIAL_PATH = re.compile(r"/api/v1/sensors/[^/]+/credentials/?")


class RequestRateLimitMiddleware:
    """Apply bounded per-client fixed-window limits to ingestion and sensor credentials."""

    def __init__(
        self,
        app: Callable[..., Awaitable[None]],
        *,
        ingestion_limit: int = 120,
        credential_limit: int = 10,
        window_seconds: int = 60,
        max_entries: int = 8192,
    ) -> None:
        if min(ingestion_limit, credential_limit, window_seconds, max_entries) < 1:
            raise ValueError("Rate-limit settings must be positive")
        self.app = app
        self.ingestion_limit = ingestion_limit
        self.credential_limit = credential_limit
        self.window_seconds = window_seconds
        self.max_entries = max_entries
        self._windows: dict[tuple[str, str], tuple[float, int]] = {}
        self._lock = threading.Lock()

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[..., Awaitable[dict[str, Any]]],
        send: Callable[..., Awaitable[None]],
    ) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "").upper()
        path = scope.get("path", "")
        if method == "POST" and _INGESTION_PATH.fullmatch(path):
            bucket, limit = "ingestion", self.ingestion_limit
        elif method in {"PUT", "DELETE"} and _SENSOR_CREDENTIAL_PATH.fullmatch(path):
            bucket, limit = "sensor_credentials", self.credential_limit
        else:
            await self.app(scope, receive, send)
            return

        client = scope.get("client")
        remote = str(client[0]) if client else "unknown"
        now = time.monotonic()
        key = (remote, bucket)
        with self._lock:
            expired = [
                item for item, (started, _) in self._windows.items()
                if now - started >= self.window_seconds
            ]
            for item in expired:
                self._windows.pop(item, None)

            started, count = self._windows.get(key, (now, 0))
            if count >= limit:
                retry_after = max(1, math.ceil(self.window_seconds - (now - started)))
                rejected = True
            else:
                if key not in self._windows and len(self._windows) >= self.max_entries:
                    self._windows.pop(next(iter(self._windows)))
                self._windows[key] = (started, count + 1)
                retry_after = 0
                rejected = False

        if rejected:
            body = json.dumps({"detail": "Rate limit exceeded"}).encode()
            await send({
                "type": "http.response.start",
                "status": 429,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"retry-after", str(retry_after).encode()),
                ],
            })
            await send({"type": "http.response.body", "body": body})
            return

        await self.app(scope, receive, send)
