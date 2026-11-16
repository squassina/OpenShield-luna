import asyncio

import pytest

from openshield.core.request_limits import RequestBodyLimitMiddleware

MAX_BODY_BYTES = 5 * 1024 * 1024
INGESTION_PATHS = [
    "/api/v1/sensors/sensor-lab/events",
    "/api/v1/dns/pihole-lab/queries",
]


async def invoke_middleware(
    path: str,
    chunks: list[bytes],
    *,
    headers: list[tuple[bytes, bytes]] | None = None,
) -> tuple[int, bool]:
    received = iter(chunks)
    remaining = len(chunks)
    app_called = False
    messages: list[dict[str, object]] = []

    async def receive() -> dict[str, object]:
        nonlocal remaining
        try:
            body = next(received)
        except StopIteration:
            return {"type": "http.request", "body": b"", "more_body": False}
        remaining -= 1
        return {
            "type": "http.request",
            "body": body,
            "more_body": remaining > 0,
        }

    async def app(scope, app_receive, send) -> None:
        nonlocal app_called
        app_called = True
        while True:
            message = await app_receive()
            if not message.get("more_body", False):
                break
        await send({
            "type": "http.response.start",
            "status": 204,
            "headers": [],
        })
        await send({"type": "http.response.body", "body": b""})

    async def send(message: dict[str, object]) -> None:
        messages.append(message)

    middleware = RequestBodyLimitMiddleware(app, MAX_BODY_BYTES)
    await middleware(
        {
            "type": "http",
            "method": "POST",
            "path": path,
            "headers": headers or [],
        },
        receive,
        send,
    )
    status = next(
        message["status"] for message in messages
        if message["type"] == "http.response.start"
    )
    return status, app_called


@pytest.mark.parametrize("path", INGESTION_PATHS)
def test_ingestion_body_limit_accepts_exactly_five_mib(path: str) -> None:
    status, app_called = asyncio.run(
        invoke_middleware(path, [b"x" * MAX_BODY_BYTES])
    )
    assert status == 204
    assert app_called


@pytest.mark.parametrize("path", INGESTION_PATHS)
def test_ingestion_body_limit_rejects_chunked_body_over_five_mib(path: str) -> None:
    status, app_called = asyncio.run(
        invoke_middleware(path, [b"x" * MAX_BODY_BYTES, b"x"])
    )
    assert status == 413
    assert app_called


@pytest.mark.parametrize("path", INGESTION_PATHS)
@pytest.mark.parametrize("value", [b"", b"abc", b"-1", b"1.5"])
def test_ingestion_body_limit_rejects_malformed_content_length(path: str, value: bytes) -> None:
    status, app_called = asyncio.run(
        invoke_middleware(path, [], headers=[(b"content-length", value)])
    )
    assert status == 400
    assert not app_called


@pytest.mark.parametrize("path", INGESTION_PATHS)
def test_ingestion_body_limit_rejects_declared_oversize_before_reading(path: str) -> None:
    status, app_called = asyncio.run(
        invoke_middleware(
            path,
            [],
            headers=[(b"content-length", str(MAX_BODY_BYTES + 1).encode())],
        )
    )
    assert status == 413
    assert not app_called


def test_ingestion_body_limit_rejects_duplicate_content_length_headers() -> None:
    status, app_called = asyncio.run(
        invoke_middleware(
            INGESTION_PATHS[0],
            [],
            headers=[(b"content-length", b"1"), (b"content-length", b"1")],
        )
    )
    assert status == 400
    assert not app_called
