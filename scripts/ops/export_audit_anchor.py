"""Export a verified OpenShield audit chain to a private NDJSON file for WORM upload."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPOSITORY_ROOT / "backend"))

from openshield.core.storage import PostgresStore


def export_snapshot(database_url: str, output_path: Path) -> dict[str, object]:
    output_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(output_path, flags, 0o600)
    store = PostgresStore(database_url)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            store.open()
            result = store.export_audit_snapshot(output)
        if result["valid"] is not True:
            output_path.unlink(missing_ok=True)
            raise RuntimeError(
                f"Audit chain verification failed: {result.get('error') or 'unknown error'}"
            )
        os.chmod(output_path, 0o600)
        return result
    except Exception:
        output_path.unlink(missing_ok=True)
        raise
    finally:
        store.close()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Export a verified audit chain to a private NDJSON file."
    )
    parser.add_argument("--output", required=True, type=Path, help="New output file path")
    args = parser.parse_args()

    database_url = os.getenv("OPENSHIELD_DATABASE_URL", "").strip()
    if not database_url:
        parser.error("OPENSHIELD_DATABASE_URL is required")

    try:
        result = export_snapshot(database_url, args.output)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"Audit export failed: {exc}", file=sys.stderr)
        return 1

    print(json.dumps({
        "valid": result["valid"],
        "records_checked": result["records_checked"],
        "last_audit_id": result["last_audit_id"],
        "head_hash": result["head_hash"],
        "records_sha256": result["records_sha256"],
        "generated_at": result["generated_at"],
        "output": str(args.output),
        "mode": "0600",
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
