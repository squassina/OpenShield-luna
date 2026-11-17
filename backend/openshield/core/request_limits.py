from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from typing import Any

_MAX_BODY_PATH = re.compile(
    r"/api/v1/(?:events|sensors/[^/]+/events|dns/[^/]+/queries)/?"
)


class RequestBodyTooLarge(Exception):
    pass


class RequestBodyLimitMiddleware:
    """Enforce streaming body limits on sensor and DNS ingestion endpoints."""

    def __init__(self, app: Callable[..., Awaitable[None]], max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[..., Awaitable[dict[str, Any]]],
        send: Callable[..., Awaitable[None]],
    ) -> None:
        if (
            scope.get("type") != "http"
            or scope.get("method") != "POST"
            or not _MAX_BODY_PATH.fullmatch(scope.get("path", ""))
        ):
            await self.app(scope, receive, send)
            return

        content_lengths = [
            value
            for name, value in scope.get("headers", [])
            if name.lower() == b"content-length"
        ]
        if len(content_lengths) > 1:
            await self._reject(send, 400, "Invalid Content-Length header")
            return
        if content_lengths:
            raw_length = content_lengths[0]
            if not raw_length or not raw_length.isdigit():
                await self._reject(send, 400, "Invalid Content-Length header")
                return
            try:
                declared_length = int(raw_length)
            except ValueError:
                await self._reject(send, 400, "Invalid Content-Length header")
                return
            if declared_length > self.max_body_bytes:
                await self._reject(send, 413, "Request body exceeds 5 MiB")
                return

        received_bytes = 0
        response_started = False

        async def limited_receive() -> dict[str, Any]:
            nonlocal received_bytes
            message = await receive()
            if message["type"] == "http.request":
                received_bytes += len(message.get("body", b""))
                if received_bytes > self.max_body_bytes:
                    raise RequestBodyTooLarge
            return message

        async def tracked_send(message: dict[str, Any]) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracked_send)
        except RequestBodyTooLarge:
            if response_started:
                raise
            await self._reject(send, 413, "Request body exceeds 5 MiB")

    @staticmethod
    async def _reject(send: Callable[..., Awaitable[None]], status: int, detail: str) -> None:
        body = ('{"detail":"' + detail + '"}').encode()
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        })
        await send({"type": "http.response.body", "body": body})
