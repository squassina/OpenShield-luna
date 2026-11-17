import asyncio

from openshield.core.rate_limits import RequestRateLimitMiddleware


async def invoke(
    middleware: RequestRateLimitMiddleware,
    *,
    path: str,
    method: str = "POST",
    remote: str = "192.0.2.10",
) -> tuple[int, bool, dict[bytes, bytes]]:
    app_called = False
    messages: list[dict[str, object]] = []

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def app(scope, app_receive, send) -> None:
        nonlocal app_called
        app_called = True
        await send({
            "type": "http.response.start",
            "status": 202,
            "headers": [],
        })
        await send({"type": "http.response.body", "body": b""})

    async def send(message: dict[str, object]) -> None:
        messages.append(message)

    middleware.app = app
    await middleware(
        {
            "type": "http",
            "method": method,
            "path": path,
            "client": (remote, 12345),
        },
        receive,
        send,
    )
    start = next(
        message for message in messages
        if message["type"] == "http.response.start"
    )
    return (
        start["status"],
        app_called,
        dict(start.get("headers", [])),
    )


def test_ingestion_rate_limit_returns_429_and_retry_after() -> None:
    middleware = RequestRateLimitMiddleware(
        lambda *_: None, ingestion_limit=2, credential_limit=1, window_seconds=60
    )

    assert asyncio.run(invoke(middleware, path="/api/v1/sensors/zeek/events"))[0] == 202
    assert asyncio.run(invoke(middleware, path="/api/v1/events"))[0] == 202
    status, app_called, headers = asyncio.run(
        invoke(middleware, path="/api/v1/dns/pihole/queries")
    )

    assert status == 429
    assert not app_called
    assert int(headers[b"retry-after"]) > 0


def test_rate_limit_is_scoped_to_remote_client() -> None:
    middleware = RequestRateLimitMiddleware(
        lambda *_: None, ingestion_limit=1, credential_limit=1
    )

    assert asyncio.run(invoke(middleware, path="/api/v1/events"))[0] == 202
    assert asyncio.run(
        invoke(middleware, path="/api/v1/events", remote="192.0.2.11")
    )[0] == 202
    assert asyncio.run(invoke(middleware, path="/api/v1/events"))[0] == 429


def test_sensor_credential_rotation_has_separate_lower_limit() -> None:
    middleware = RequestRateLimitMiddleware(
        lambda *_: None, ingestion_limit=1, credential_limit=2
    )

    path = "/api/v1/sensors/zeek/credentials"
    assert asyncio.run(invoke(middleware, path=path, method="PUT"))[0] == 202
    assert asyncio.run(invoke(middleware, path=path, method="DELETE"))[0] == 202
    assert asyncio.run(invoke(middleware, path=path, method="PUT"))[0] == 429


def test_unrelated_requests_are_not_rate_limited() -> None:
    middleware = RequestRateLimitMiddleware(
        lambda *_: None, ingestion_limit=1, credential_limit=1
    )

    for _ in range(3):
        status, app_called, _ = asyncio.run(
            invoke(middleware, path="/api/v1/events", method="GET")
        )
        assert status == 202
        assert app_called


def test_rate_limit_settings_must_be_positive() -> None:
    import pytest

    with pytest.raises(ValueError, match="must be positive"):
        RequestRateLimitMiddleware(lambda *_: None, ingestion_limit=0)
