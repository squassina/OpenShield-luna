#!/usr/bin/env python3
"""Refresh the pinned AdGuard CNAME tracker feed from its upstream Git commit."""

import json
import os
import re
from datetime import datetime
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "backend/openshield/privacy/data"
API_URL = "https://api.github.com/repos/AdguardTeam/cname-trackers/commits/master"
FEED_PATH = "data/combined_original_trackers_justdomains.txt"
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
DEFAULT_DOWNLOAD_BYTES = 2 * 1024 * 1024
MIN_TRACKER_DOMAINS = 50
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+$"
)
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


def download(url: str, limit: int) -> bytes:
    """Read a complete response in bounded chunks; reject oversize/truncated bodies."""
    if limit < 1:
        raise ValueError("Download size limit must be positive")
    request = Request(url, headers={"User-Agent": "OpenShield-feed-updater"})
    with urlopen(request, timeout=20) as response:
        raw_length = response.headers.get("Content-Length")
        expected_length = None
        if raw_length is not None:
            try:
                expected_length = int(raw_length)
            except ValueError as exc:
                raise RuntimeError("Upstream response has an invalid Content-Length") from exc
            if expected_length < 0:
                raise RuntimeError("Upstream response has an invalid Content-Length")
            if expected_length > limit:
                raise RuntimeError("Upstream response exceeds the configured size limit")

        chunks = []
        total = 0
        while True:
            chunk = response.read(min(64 * 1024, limit - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise RuntimeError("Upstream response exceeds the configured size limit")
            chunks.append(chunk)

        if expected_length is not None and total != expected_length:
            raise RuntimeError("Upstream response was truncated")
    return b"".join(chunks)


def _download_limit() -> int:
    raw = os.getenv("OPENSHIELD_CNAME_TRACKER_MAX_BYTES", str(DEFAULT_DOWNLOAD_BYTES))
    try:
        limit = int(raw)
    except ValueError as exc:
        raise RuntimeError("OPENSHIELD_CNAME_TRACKER_MAX_BYTES must be an integer") from exc
    if not 1024 <= limit <= MAX_DOWNLOAD_BYTES:
        raise RuntimeError(
            "OPENSHIELD_CNAME_TRACKER_MAX_BYTES must be between 1024 and 67108864"
        )
    return limit


def _parse_feed(payload: bytes) -> tuple[list[str], str]:
    try:
        source = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError("Upstream tracker feed is not valid UTF-8") from exc

    updated_at = next(
        (
            line.split(":", 1)[1].strip()
            for line in source.splitlines()
            if line.startswith("# TimeUpdated:")
        ),
        None,
    )
    if not updated_at:
        raise RuntimeError("Upstream tracker feed is missing its TimeUpdated header")
    try:
        timestamp = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeError("Upstream tracker feed has an invalid TimeUpdated value") from exc
    if timestamp.tzinfo is None:
        raise RuntimeError("Upstream tracker feed TimeUpdated must include a timezone")

    domains = sorted({
        line.strip().lower()
        for line in source.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    })
    if len(domains) < MIN_TRACKER_DOMAINS:
        raise RuntimeError(
            f"Upstream tracker feed contains fewer than {MIN_TRACKER_DOMAINS} domains"
        )
    if any(not DOMAIN_RE.fullmatch(domain) for domain in domains):
        raise RuntimeError("Upstream tracker feed contains invalid domain entries")
    return domains, updated_at


def main() -> None:
    limit = _download_limit()
    commit = json.loads(download(API_URL, limit))
    sha = commit.get("sha") if isinstance(commit, dict) else None
    if not isinstance(sha, str) or not COMMIT_RE.fullmatch(sha):
        raise RuntimeError("Upstream tracker commit response has an invalid SHA")

    raw_url = f"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/{sha}/{FEED_PATH}"
    domains, updated_at = _parse_feed(download(raw_url, limit))

    metadata = {
        "source": "AdGuard CNAME original trackers list",
        "source_url": "https://github.com/AdguardTeam/cname-trackers",
        "feed_url": "https://github.com/AdguardTeam/cname-trackers/blob/master/" + FEED_PATH,
        "license": "MIT",
        "source_commit": sha,
        "updated_at": updated_at,
        "entry_count": len(domains),
    }
    DATA.mkdir(parents=True, exist_ok=True)
    feed_path = DATA / "cname_trackers_justdomains.txt"
    metadata_path = DATA / "cname_trackers_metadata.json"
    feed_tmp = feed_path.with_suffix(".txt.tmp")
    metadata_tmp = metadata_path.with_suffix(".json.tmp")
    feed_tmp.write_text(
        "# Derived from AdGuardTeam/cname-trackers; see THIRD_PARTY_NOTICES.md\n"
        + "\n".join(domains) + "\n"
    )
    metadata_tmp.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    feed_tmp.replace(feed_path)
    metadata_tmp.replace(metadata_path)


if __name__ == "__main__":
    main()
