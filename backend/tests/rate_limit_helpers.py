from fastapi import FastAPI

from openshield.core.rate_limits import RequestRateLimitMiddleware


def reset_rate_limits(app: FastAPI) -> None:
    stack = app.middleware_stack
    if stack is None:
        stack = app.build_middleware_stack()
        app.middleware_stack = stack

    while stack is not None:
        if isinstance(stack, RequestRateLimitMiddleware):
            stack.reset()
            return
        stack = getattr(stack, "app", None)

    raise AssertionError("RequestRateLimitMiddleware not found in application stack")
