#!/usr/bin/env python3
"""Refresh the pinned AdGuard CNAME tracker feed from its upstream Git commit."""
import json
import re
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "backend/openshield/privacy/data"
API_URL = "https://api.github.com/repos/AdguardTeam/cname-trackers/commits/master"
FEED_PATH = "data/combined_original_trackers_justdomains.txt"
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+$"
)


def download(url: str, limit: int) -> bytes:
    request = Request(url, headers={"User-Agent": "OpenShield-feed-updater"})
    with urlopen(request, timeout=20) as response:
        payload = response.read(limit + 1)
    if len(payload) > limit:
        raise RuntimeError("Upstream tracker feed exceeds the size limit")
    return payload


def main() -> None:
    commit = json.loads(download(API_URL, 256_000))
    sha = commit["sha"]
    raw_url = f"https://raw.githubusercontent.com/AdguardTeam/cname-trackers/{sha}/{FEED_PATH}"
    source = download(raw_url, 256_000).decode("utf-8")
    updated_at = next(
        (line.split(":", 1)[1].strip() for line in source.splitlines()
         if line.startswith("# TimeUpdated:")),
        None,
    )
    domains = sorted({
        line.strip().lower() for line in source.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    })
    if not updated_at or len(domains) < 10 or any(not DOMAIN_RE.fullmatch(item) for item in domains):
        raise RuntimeError("Upstream tracker feed failed validation")
    DATA.mkdir(parents=True, exist_ok=True)
    (DATA / "cname_trackers_justdomains.txt").write_text(
        "# Derived from AdGuardTeam/cname-trackers; see THIRD_PARTY_NOTICES.md\n"
        + "\n".join(domains) + "\n"
    )
    metadata = {
        "source": "AdGuard CNAME original trackers list",
        "source_url": "https://github.com/AdguardTeam/cname-trackers",
        "feed_url": "https://github.com/AdguardTeam/cname-trackers/blob/master/" + FEED_PATH,
        "license": "MIT",
        "source_commit": sha,
        "updated_at": updated_at,
    }
    (DATA / "cname_trackers_metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n"
    )


if __name__ == "__main__":
    main()
