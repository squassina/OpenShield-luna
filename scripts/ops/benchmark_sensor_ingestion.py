#!/usr/bin/env python3
"""Measure sequential synthetic Suricata/Zeek ingestion against an existing OpenShield sensor."""

from __future__ import annotations

import argparse
import base64
import json
import math
import os
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from uuid import uuid4


def percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    return ordered[max(0, math.ceil(quantile * len(ordered)) - 1)]


class Api:
    def __init__(self, base_url: str, timeout: float) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        username = os.getenv("OPENSHIELD_BENCHMARK_USERNAME")
        password = os.getenv("OPENSHIELD_BENCHMARK_PASSWORD")
        if bool(username) != bool(password):
            raise ValueError(
                "Set both OPENSHIELD_BENCHMARK_USERNAME and "
                "OPENSHIELD_BENCHMARK_PASSWORD, or neither"
            )
        self.authorization = None
        if username and password:
            token = base64.b64encode(f"{username}:{password}".encode()).decode()
            self.authorization = f"Basic {token}"

    def request(self, path: str, payload: object | None = None) -> dict:
        data = None if payload is None else json.dumps(payload).encode()
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if self.authorization:
            headers["Authorization"] = self.authorization
        request = urllib.request.Request(
            self.base_url + path, data=data, headers=headers,
            method="GET" if data is None else "POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                result = json.loads(response.read())
        except urllib.error.HTTPError as exc:
            detail = exc.read(2048).decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {exc.code} for {path}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Request failed for {path}: {exc.reason}") from exc
        if not isinstance(result, dict):
            raise RuntimeError(f"Unexpected API response for {path}")
        return result


def make_record(kind: str, sequence: int) -> dict:
    now = time.time()
    unique = f"openshield-bench-{uuid4().hex}-{sequence}"
    if kind == "zeek":
        return {
            "_path": "conn",
            "ts": now,
            "uid": unique,
            "id.orig_h": "192.0.2.10",
            "id.orig_p": 40000 + sequence % 20000,
            "id.resp_h": "198.51.100.20",
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "conn_state": "SF",
        }
    return {
        "timestamp": datetime.fromtimestamp(now, UTC).isoformat(),
        "event_type": "flow",
        "src_ip": "192.0.2.10",
        "src_port": 40000 + sequence % 20000,
        "dest_ip": "198.51.100.20",
        "dest_port": 443,
        "proto": "TCP",
        "community_id": unique,
    }


def count_events(api: Api, integration_id: str) -> int:
    query = urllib.parse.urlencode({"integration_id": integration_id, "limit": 1000})
    path = f"/api/v1/events?{query}"
    cursor = None
    total = 0
    while True:
        page_path = path
        if cursor:
            page_path += "&" + urllib.parse.urlencode({"cursor": cursor})
        result = api.request(page_path)
        items = result.get("items")
        if not isinstance(items, list):
            raise RuntimeError("Event listing response has no items array")
        total += len(items)
        cursor = result.get("next_cursor")
        if not cursor:
            return total


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--integration-id", required=True)
    parser.add_argument("--kind", choices=("suricata", "zeek"), required=True)
    parser.add_argument("--events", type=int, default=1000)
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    if not 1 <= args.events <= 100_000:
        parser.error("--events must be between 1 and 100000")
    if not 1 <= args.batch_size <= 500:
        parser.error("--batch-size must be between 1 and 500")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    return args


def main() -> int:
    args = parse_args()
    api = Api(args.base_url, args.timeout)
    health = api.request("/health/ready")
    if health.get("status") != "ready":
        raise RuntimeError("OpenShield Node is not ready")

    baseline = count_events(api, args.integration_id)
    latencies: list[float] = []
    accepted = duplicates = sent = 0
    started = time.perf_counter()

    while sent < args.events:
        size = min(args.batch_size, args.events - sent)
        records = [make_record(args.kind, sent + index) for index in range(size)]
        path = f"/api/v1/sensors/{urllib.parse.quote(args.integration_id, safe='')}/events"
        request_started = time.perf_counter()
        result = api.request(path, records)
        latencies.append(time.perf_counter() - request_started)
        received = result.get("received")
        batch_accepted = result.get("accepted")
        batch_duplicates = result.get("duplicates")
        if received != size or not isinstance(batch_accepted, int) or not isinstance(
            batch_duplicates, int
        ):
            raise RuntimeError(f"Unexpected ingestion response: {result}")
        if batch_accepted + batch_duplicates != size:
            raise RuntimeError(f"Batch accounting mismatch: {result}")
        accepted += batch_accepted
        duplicates += batch_duplicates
        sent += size

    elapsed = time.perf_counter() - started
    read_started = time.perf_counter()
    final_count = count_events(api, args.integration_id)
    read_elapsed = time.perf_counter() - read_started
    observed_delta = final_count - baseline
    if observed_delta < accepted:
        raise RuntimeError(
            f"Read-after-write check failed: expected at least {accepted} new events, "
            f"observed {observed_delta}"
        )

    report = {
        "base_url": args.base_url,
        "integration_id": args.integration_id,
        "kind": args.kind,
        "requested_events": args.events,
        "batch_size": args.batch_size,
        "accepted": accepted,
        "duplicates": duplicates,
        "elapsed_seconds": round(elapsed, 3),
        "ingestion_events_per_second": round(accepted / elapsed, 2) if elapsed else 0,
        "read_elapsed_seconds": round(read_elapsed, 3),
        "read_events_per_second": (
            round(observed_delta / read_elapsed, 2) if read_elapsed else 0
        ),
        "request_latency_ms": {
            "p50": round(percentile(latencies, 0.50) * 1000, 2),
            "p95": round(percentile(latencies, 0.95) * 1000, 2),
            "p99": round(percentile(latencies, 0.99) * 1000, 2),
            "mean": round(statistics.mean(latencies) * 1000, 2) if latencies else 0,
        },
        "events_before": baseline,
        "events_after": final_count,
        "read_after_write_delta": observed_delta,
        "read_after_write_verified": True,
    }
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, ValueError) as exc:
        print(f"benchmark failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
