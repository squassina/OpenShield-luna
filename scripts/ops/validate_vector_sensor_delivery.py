"""Validate Vector sensor config and exercise its HTTP payload against a local stub."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


VECTOR_IMAGE = "timberio/vector:0.62.0"
SENSOR_PATHS = {
    "suricata": "/api/v1/sensors/vector-ci/events",
    "zeek": "/api/v1/sensors/vector-ci/events",
}
ALLOWED_TYPES = {
    "suricata": {"alert", "flow", "dns", "http", "tls", "ssh", "anomaly"},
    "zeek": {"conn", "dns", "http", "ssl"},
}


class DeliveryState:
    def __init__(self, expected: list[dict[str, Any]]) -> None:
        self.expected = expected
        self.events: list[dict[str, Any]] = []
        self.error: str | None = None
        self.delivered = threading.Event()
        self.lock = threading.Lock()


def _read_records(path: Path, kind: str) -> list[dict[str, Any]]:
    records = [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if not records or any(not isinstance(record, dict) for record in records):
        raise ValueError("Fixture must contain one or more JSON objects")
    for record in records:
        event_type = record.get("event_type") if kind == "suricata" else record.get("_path")
        if event_type not in ALLOWED_TYPES[kind]:
            raise ValueError(f"Fixture contains unsupported {kind} type: {event_type!r}")
    return records


def _read_chunked(handler: BaseHTTPRequestHandler) -> bytes:
    chunks: list[bytes] = []
    while True:
        size_line = handler.rfile.readline().split(b";", 1)[0].strip()
        size = int(size_line, 16)
        if size == 0:
            handler.rfile.readline()
            break
        chunks.append(handler.rfile.read(size))
        handler.rfile.read(2)
    return b"".join(chunks)


def _make_handler(state: DeliveryState, sensor_path: str, health_path: str):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, _format: str, *_args: object) -> None:
            return

        def _reply(self, status: int, payload: dict[str, object]) -> None:
            data = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:
            if self.path == health_path:
                self._reply(200, {"status": "ready"})
            else:
                self._reply(404, {"detail": "not found"})

        def do_HEAD(self) -> None:
            if self.path == health_path:
                self.send_response(200)
                self.end_headers()
            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self) -> None:
            if self.path != sensor_path:
                self._reply(404, {"detail": "unexpected path"})
                with state.lock:
                    state.error = f"Unexpected HTTP path: {self.path}"
                return
            if self.headers.get("Authorization") != "Bearer vector-ci-token":
                with state.lock:
                    state.error = "Vector did not send the expected bearer token"
                self._reply(401, {"detail": "authentication required"})
                return
            if not self.headers.get("Content-Type", "").lower().startswith("application/json"):
                with state.lock:
                    state.error = "Vector did not send application/json"
                self._reply(415, {"detail": "JSON required"})
                return
            try:
                if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                    body = _read_chunked(self)
                else:
                    length = int(self.headers.get("Content-Length", "0"))
                    body = self.rfile.read(length)
                records = json.loads(body)
                if not isinstance(records, list) or any(
                    not isinstance(record, dict) for record in records
                ):
                    raise ValueError("Expected a JSON array of objects")
            except (ValueError, json.JSONDecodeError) as exc:
                with state.lock:
                    state.error = f"Invalid batch JSON: {exc}"
                self._reply(400, {"detail": "invalid JSON batch"})
                return

            with state.lock:
                state.events.extend(records)
                if len(state.events) > len(state.expected):
                    state.error = "Vector delivered more records than the fixture contains"
                elif state.events == state.expected:
                    state.delivered.set()
                elif state.events != state.expected[: len(state.events)]:
                    state.error = "Vector changed, reordered, or duplicated fixture records"

            self._reply(
                202,
                {
                    "received": len(records),
                    "accepted": len(records),
                    "duplicates": 0,
                },
            )

    return Handler


def _docker_run(
    command: list[str], *, timeout: int = 180, check: bool = True
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if check and result.returncode != 0:
        detail = (result.stdout + result.stderr)[-12000:]
        raise RuntimeError(f"Docker command failed ({result.returncode}):\n{detail}")
    return result


def validate_and_deliver(
    kind: str,
    config_path: Path,
    fixture_path: Path,
    container_file: str,
    image: str,
    timeout_seconds: int,
) -> int:
    expected = _read_records(fixture_path, kind)
    invalid_record = (
        {"timestamp": "2026-11-17T12:01:00.000000+0000", "event_type": "stats"}
        if kind == "suricata"
        else {"ts": 1794916804.0, "_path": "notice", "uid": "C-vector-unsupported"}
    )

    with tempfile.TemporaryDirectory(prefix=f"openshield-vector-{kind}-") as temporary:
        temp_dir = Path(temporary)
        os.chmod(temp_dir, 0o777)
        mounted_fixture = temp_dir / "sensor.log"
        fixture_text = fixture_path.read_text(encoding="utf-8").rstrip("\n")
        mounted_fixture.write_text(
            fixture_text + "\n{malformed-json}\n" + json.dumps(invalid_record) + "\n",
            encoding="utf-8",
        )

        server_state = DeliveryState(expected)
        server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            _make_handler(server_state, SENSOR_PATHS[kind], "/health/ready"),
        )
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        container_name = f"openshield-vector-{kind}-{uuid.uuid4().hex[:10]}"
        port = int(server.server_address[1])
        env = [
            "-e",
            "VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true",
            "-e",
            f"OPENSHIELD_NODE_URL=http://127.0.0.1:{port}",
            "-e",
            "OPENSHIELD_SENSOR_TOKEN=vector-ci-token",
            "-e",
            "OPENSHIELD_SENSOR_INTEGRATION_ID=vector-ci",
        ]
        mounts = [
            "-v",
            f"{config_path.resolve()}:/etc/vector/vector.yaml:ro",
            "-v",
            f"{mounted_fixture}:{container_file}:ro",
            "-v",
            f"{temp_dir}:/var/lib/vector",
        ]
        base = ["docker", "run", "--rm", "--network", "host", *env, *mounts]
        container_started = False
        try:
            _docker_run(
                [
                    *base,
                    "--entrypoint",
                    "vector",
                    image,
                    "validate",
                    "--no-environment",
                    "/etc/vector/vector.yaml",
                ]
            )
            started = _docker_run(
                [
                    "docker",
                    "run",
                    "--detach",
                    "--rm",
                    "--name",
                    container_name,
                    "--network",
                    "host",
                    *env,
                    *mounts,
                    "--entrypoint",
                    "vector",
                    image,
                    "--config",
                    "/etc/vector/vector.yaml",
                    "--require-healthy",
                ]
            )
            container_started = True
            if not started.stdout.strip():
                raise RuntimeError("Docker did not return the Vector container ID")

            deadline = time.monotonic() + timeout_seconds
            while time.monotonic() < deadline:
                with server_state.lock:
                    error = server_state.error
                    delivered = server_state.delivered.is_set()
                if error:
                    raise RuntimeError(error)
                if delivered:
                    return len(expected)
                running = _docker_run(
                    [
                        "docker",
                        "inspect",
                        "--format",
                        "{{.State.Running}}",
                        container_name,
                    ],
                    timeout=10,
                    check=False,
                )
                if running.returncode != 0 or running.stdout.strip() != "true":
                    logs = _docker_run(
                        ["docker", "logs", "--tail", "80", container_name],
                        timeout=10,
                        check=False,
                    )
                    raise RuntimeError(
                        "Vector exited before delivering the fixture:\n"
                        + logs.stdout
                        + logs.stderr
                    )
                server_state.delivered.wait(0.2)

            logs = _docker_run(
                ["docker", "logs", "--tail", "100", container_name],
                timeout=10,
                check=False,
            )
            with server_state.lock:
                received = len(server_state.events)
                error = server_state.error
            raise TimeoutError(
                f"Timed out waiting for {len(expected)} {kind} events; "
                f"received {received}. {error or ''}\n{logs.stdout}{logs.stderr}"
            )
        finally:
            if container_started:
                _docker_run(
                    ["docker", "stop", "--time", "10", container_name],
                    timeout=20,
                    check=False,
                )
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=2)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=("suricata", "zeek"), required=True)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--container-file", required=True)
    parser.add_argument("--image", default=VECTOR_IMAGE)
    parser.add_argument("--timeout-seconds", type=int, default=45)
    args = parser.parse_args()
    if not 5 <= args.timeout_seconds <= 180:
        parser.error("--timeout-seconds must be between 5 and 180")
    return args


def main() -> int:
    args = parse_args()
    if shutil.which("docker") is None:
        print("Docker CLI is required for Vector config validation.", file=sys.stderr)
        return 2
    try:
        count = validate_and_deliver(
            args.kind,
            args.config,
            args.fixture,
            args.container_file,
            args.image,
            args.timeout_seconds,
        )
    except (OSError, RuntimeError, subprocess.SubprocessError, TimeoutError, ValueError) as exc:
        print(f"Vector {args.kind} validation failed: {exc}", file=sys.stderr)
        return 1
    print(f"Vector {args.kind}: validated config and delivered {count} fixture events as JSON array.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
