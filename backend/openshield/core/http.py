from __future__ import annotations

import ssl
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Credential-bearing integration requests must never follow redirects.
        return None


def safe_urlopen(
    request: Request, *, timeout: float, context: ssl.SSLContext | None = None,
):
    handlers = [_RejectRedirects()]
    if context is not None:
        handlers.append(HTTPSHandler(context=context))
    return build_opener(*handlers).open(request, timeout=timeout)
