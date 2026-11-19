#!/usr/bin/env python3
"""Validate relative Markdown links in repository documentation."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
LINK_RE = re.compile(r"!?\[[^\]]*\]\((<[^>]*>|(?:\\.|[^()\s])*)(?:\s+[^)]*)?\)")
FENCE_RE = re.compile(r"^\s*(?:```|~~~).*$", re.MULTILINE)


def _without_fenced_code(content: str) -> str:
    lines = content.splitlines()
    output: list[str] = []
    fence: str | None = None
    for line in lines:
        stripped = line.lstrip()
        marker = "```" if stripped.startswith("```") else "~~~" if stripped.startswith("~~~") else None
        if marker:
            if fence is None:
                fence = marker
            elif marker == fence:
                fence = None
            continue
        if fence is None:
            output.append(line)
    return "\n".join(output)


def _resolve_target(source: Path, destination: str) -> Path | None:
    raw = destination.strip()
    if raw.startswith("<") and raw.endswith(">"):
        raw = raw[1:-1]
    parsed = urlsplit(raw)
    if parsed.scheme or parsed.netloc:
        return None
    if not parsed.path:
        return source
    decoded = unquote(parsed.path)
    candidate = (source.parent / decoded).resolve()
    try:
        candidate.relative_to(ROOT)
    except ValueError:
        return candidate
    if candidate.is_dir():
        for index_name in ("README.md", "index.md"):
            index = candidate / index_name
            if index.is_file():
                return index
    return candidate


def main() -> int:
    markdown_files = sorted(
        path for path in ROOT.rglob("*.md")
        if ".git" not in path.parts
        and "node_modules" not in path.parts
        and ".venv" not in path.parts
    )
    failures: list[str] = []
    checked = 0
    for source in markdown_files:
        content = _without_fenced_code(source.read_text(encoding="utf-8"))
        for match in LINK_RE.finditer(content):
            destination = match.group(1)
            parsed = urlsplit(destination.strip("<>"))
            if parsed.scheme or parsed.netloc:
                continue
            target = _resolve_target(source, destination)
            if target is None:
                continue
            checked += 1
            if not target.exists():
                relative = source.relative_to(ROOT)
                failures.append(f"{relative}: broken link target {destination}")

    if failures:
        print("\n".join(failures), file=sys.stderr)
        print(f"Found {len(failures)} broken links across {checked} local links.", file=sys.stderr)
        return 1
    print(f"Validated {checked} local Markdown links across {len(markdown_files)} files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
