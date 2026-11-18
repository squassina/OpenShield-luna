import base64
import json
import sys
from urllib.request import Request

import pytest

from scripts.ops import benchmark_sensor_ingestion as benchmark


def test_percentile_uses_nearest_rank_and_handles_empty_values() -> None:
    assert benchmark.percentile([], 0.95) == 0
    assert benchmark.percentile([4.0, 1.0, 3.0, 2.0], 0.50) == 2.0
    assert benchmark.percentile([4.0, 1.0, 3.0, 2.0], 0.95) == 4.0


def test_api_uses_basic_auth_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENSHIELD_BENCHMARK_USERNAME", "benchmark")
    monkeypatch.setenv("OPENSHIELD_BENCHMARK_PASSWORD", "secret")
    captured: list[Request] = []

    class Response:
        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def read(self) -> bytes:
            return b'{"status":"ready"}'

    def fake_urlopen(request: Request, timeout: float) -> Response:
        captured.append(request)
        assert timeout == 7
        return Response()

    monkeypatch.setattr(benchmark.urllib.request, "urlopen", fake_urlopen)
    api = benchmark.Api("http://localhost:8000/", timeout=7)

    assert api.request("/health/ready") == {"status": "ready"}
    assert captured[0].full_url == "http://localhost:8000/health/ready"
    assert captured[0].get_header("Authorization") == (
        "Basic " + base64.b64encode(b"benchmark:secret").decode()
    )


def test_api_rejects_partial_basic_auth_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENSHIELD_BENCHMARK_USERNAME", "benchmark")
    monkeypatch.delenv("OPENSHIELD_BENCHMARK_PASSWORD", raising=False)

    with pytest.raises(ValueError, match="Set both"):
        benchmark.Api("http://localhost:8000", timeout=1)


def test_count_events_follows_keyset_cursor_pages() -> None:
    class FakeApi:
        def __init__(self) -> None:
            self.paths: list[str] = []

        def request(self, path: str) -> dict:
            self.paths.append(path)
            if len(self.paths) == 1:
                return {"items": [{"event_id": "one"}, {"event_id": "two"}], "next_cursor": "abc"}
            return {"items": [{"event_id": "three"}], "next_cursor": None}

    api = FakeApi()

    assert benchmark.count_events(api, "sensor / one") == 3
    assert len(api.paths) == 2
    assert "integration_id=sensor+%2F+one" in api.paths[0]
    assert "cursor=abc" in api.paths[1]


def test_main_reports_ingestion_and_read_after_write(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class FakeApi:
        def __init__(self, base_url: str, timeout: float) -> None:
            assert base_url == "http://node:8000"
            assert timeout == 5

        def request(self, path: str, payload: object | None = None) -> dict:
            if path == "/health/ready":
                return {"status": "ready"}
            assert path == "/api/v1/sensors/zeek/events"
            assert isinstance(payload, list)
            return {"received": len(payload), "accepted": len(payload), "duplicates": 0}

    counts = iter((10, 14))
    monkeypatch.setattr(benchmark, "Api", FakeApi)
    monkeypatch.setattr(benchmark, "count_events", lambda *_: next(counts))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "benchmark_sensor_ingestion.py",
            "--base-url",
            "http://node:8000",
            "--integration-id",
            "zeek-lab",
            "--kind",
            "zeek",
            "--events",
            "4",
            "--batch-size",
            "3",
            "--timeout",
            "5",
        ],
    )

    assert benchmark.main() == 0
    report = json.loads(capsys.readouterr().out)
    assert report["accepted"] == 4
    assert report["duplicates"] == 0
    assert report["events_before"] == 10
    assert report["events_after"] == 14
    assert report["read_after_write_verified"] is True
    assert report["request_latency_ms"]["p50"] >= 0


def test_main_rejects_read_after_write_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeApi:
        def __init__(self, *_: object, **__: object) -> None:
            return None

        def request(self, path: str, payload: object | None = None) -> dict:
            if path == "/health/ready":
                return {"status": "ready"}
            assert isinstance(payload, list)
            return {"received": len(payload), "accepted": len(payload), "duplicates": 0}

    counts = iter((5, 5))
    monkeypatch.setattr(benchmark, "Api", FakeApi)
    monkeypatch.setattr(benchmark, "count_events", lambda *_: next(counts))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "benchmark_sensor_ingestion.py",
            "--integration-id",
            "zeek-lab",
            "--kind",
            "zeek",
            "--events",
            "2",
        ],
    )

    with pytest.raises(RuntimeError, match="Read-after-write check failed"):
        benchmark.main()
