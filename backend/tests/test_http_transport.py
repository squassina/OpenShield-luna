from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.error import HTTPError
from urllib.request import Request

import pytest

from openshield.core.http import safe_urlopen


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_safe_urlopen_rejects_redirects_without_forwarding_credentials(status: int) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/redirect":
                self.send_response(status)
                self.send_header("Location", "/target")
                self.end_headers()
                return
            self.server.target_requests += 1
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.target_requests = 0
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        request = Request(
            f"http://127.0.0.1:{server.server_port}/redirect",
            headers={"Authorization": "Bearer must-not-leak"},
        )
        with pytest.raises(HTTPError) as error:
            safe_urlopen(request, timeout=2)
        assert error.value.code == status
        assert server.target_requests == 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
