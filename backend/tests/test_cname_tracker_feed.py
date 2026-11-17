import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if not (ROOT / "scripts").is_dir():
    ROOT = ROOT.parent
SCRIPT = ROOT / "scripts" / "update_cname_tracker_feed.py"
SPEC = importlib.util.spec_from_file_location("update_cname_tracker_feed", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
FEED_UPDATER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FEED_UPDATER)


class FakeResponse:
    def __init__(self, payload: bytes, headers: dict[str, str] | None = None) -> None:
        self.payload = payload
        self.headers = headers or {}
        self.offset = 0
        self.read_sizes: list[int] = []

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def read(self, size: int) -> bytes:
        self.read_sizes.append(size)
        chunk = self.payload[self.offset:self.offset + size]
        self.offset += len(chunk)
        return chunk


def test_download_reads_complete_body_in_bounded_chunks(monkeypatch) -> None:
    payload = b"x" * 150_000
    response = FakeResponse(payload, {"Content-Length": str(len(payload))})
    monkeypatch.setattr(FEED_UPDATER, "urlopen", lambda *_args, **_kwargs: response)

    result = FEED_UPDATER.download("https://feed.example/data", 200_000)

    assert result == payload
    assert len(response.read_sizes) > 1
    assert max(response.read_sizes) <= 64 * 1024


def test_download_rejects_oversized_body_while_streaming(monkeypatch) -> None:
    response = FakeResponse(b"x" * 11)
    monkeypatch.setitem(FEED_UPDATER, "urlopen", lambda *_args, **_kwargs: response)

    with pytest.raises(RuntimeError, match="exceeds the configured size limit"):
        FEED_UPDATER["download"]("https://feed.example/data", 10)


def test_download_rejects_truncated_content_length(monkeypatch) -> None:
    response = FakeResponse(b"short", {"Content-Length": "10"})
    monkeypatch.setitem(FEED_UPDATER, "urlopen", lambda *_args, **_kwargs: response)

    with pytest.raises(RuntimeError, match="truncated"):
        FEED_UPDATER["download"]("https://feed.example/data", 100)


def test_download_rejects_oversized_content_length_before_reading(monkeypatch) -> None:
    response = FakeResponse(b"", {"Content-Length": "101"})
    monkeypatch.setitem(FEED_UPDATER, "urlopen", lambda *_args, **_kwargs: response)

    with pytest.raises(RuntimeError, match="exceeds the configured size limit"):
        FEED_UPDATER["download"]("https://feed.example/data", 100)
    assert response.read_sizes == []


def test_feed_parser_requires_complete_metadata_and_minimum_valid_domains() -> None:
    domains = [f"tracker-{index}.example" for index in range(60)]
    payload = (
        "# Title: CNAME trackers\n"
        "# TimeUpdated: 2026-11-05T15:48:54+00:00\n"
        + "\n".join(domains)
    ).encode()

    parsed, updated_at = FEED_UPDATER._parse_feed(payload)

    assert parsed == sorted(domains)
    assert len(parsed) == 60
    assert updated_at == "2026-11-05T15:48:54+00:00"


@pytest.mark.parametrize(
    "payload",
    [
        b"tracker.example\n",
        b"# TimeUpdated: 2026-11-05T15:48:54+00:00\n" + b"tracker.example\n" * 5,
        b"# TimeUpdated: not-a-date\n" + b"tracker.example\n" * 60,
        b"# TimeUpdated: 2026-11-05T15:48:54\n" + b"tracker.example\n" * 60,
        b"# TimeUpdated: 2026-11-05T15:48:54+00:00\n" + b"invalid domain\n" * 60,
        b"\xff",
    ],
)
def test_feed_parser_rejects_incomplete_or_malformed_payloads(payload: bytes) -> None:
    with pytest.raises(RuntimeError):
        FEED_UPDATER["_parse_feed"](payload)


def test_download_limit_is_configurable_and_bounded(monkeypatch) -> None:
    monkeypatch.setenv("OPENSHIELD_CNAME_TRACKER_MAX_BYTES", "4096")
    assert FEED_UPDATER._download_limit() == 4096

    monkeypatch.setenv("OPENSHIELD_CNAME_TRACKER_MAX_BYTES", "not-a-number")
    with pytest.raises(RuntimeError, match="must be an integer"):
        FEED_UPDATER["_download_limit"]()

    monkeypatch.setenv("OPENSHIELD_CNAME_TRACKER_MAX_BYTES", "999999999")
    with pytest.raises(RuntimeError, match="between 1024"):
        FEED_UPDATER["_download_limit"]()
