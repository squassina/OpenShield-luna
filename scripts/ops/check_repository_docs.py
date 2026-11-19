#!/usr/bin/env python3
"""Validate repository-local Markdown links and inline dashboard JavaScript syntax."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import unquote, urlsplit

_LINK = re.compile(r"!?\[[^\]]*\]\(\s*(?:<([^>]+)>|([^\s)]+))")
_SCRIPT = re.compile(r"<script\b([^>]*)>(.*?)</script\s*>", re.IGNORECASE | re.DOTALL)
_SCRIPT_TYPE = re.compile(r"""type\s*=\s*["']?([^"'\s>]+)""", re.IGNORECASE)
_SCRIPT_SRC = re.compile(r"\bsrc\s*=", re.IGNORECASE)
_IGNORED_DIRS = {".git", ".venv", "node_modules", "__pycache__", ".pytest_cache"}


def markdown_files(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("*.md")
        if not any(part in _IGNORED_DIRS for part in path.relative_to(root).parts)
    )


def check_markdown_links(root: Path) -> list[str]:
    errors: list[str] = []
    for markdown in markdown_files(root):
        content = markdown.read_text(encoding="utf-8")
        for match in _LINK.finditer(content):
            destination = match.group(1) or match.group(2) or ""
            parsed = urlsplit(destination)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            relative_path = Path(unquote(parsed.path))
            target = (
                root / relative_path.as_posix().lstrip("/")
                if relative_path.is_absolute()
                else markdown.parent / relative_path
            )
            if not target.exists():
                line = content.count("\n", 0, match.start()) + 1
                errors.append(
                    f"{markdown.relative_to(root)}:{line}: missing local link {destination}"
                )
    return errors


def check_dashboard_scripts(root: Path, node: str) -> list[str]:
    candidates = (
        root / "backend" / "openshield" / "dashboard.html",
        root / "openshield" / "dashboard.html",
    )
    dashboard = next((path for path in candidates if path.is_file()), None)
    if dashboard is None:
        return ["dashboard.html was not found"]

    html = dashboard.read_text(encoding="utf-8")
    errors: list[str] = []
    script_index = 0
    for attributes, source in _SCRIPT.findall(html):
        if _SCRIPT_SRC.search(attributes):
            continue
        match = _SCRIPT_TYPE.search(attributes)
        script_type = match.group(1).lower() if match else "text/javascript"
        if script_type not in {
            "text/javascript",
            "application/javascript",
            "module",
        }:
            continue
        script_index += 1
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".mjs",
        ) as source_file:
            source_file.write(source)
            source_file.flush()
            result = subprocess.run(
                [node, "--check", source_file.name],
                capture_output=True,
                text=True,
                check=False,
            )
        if result.returncode:
            detail = result.stderr.strip() or result.stdout.strip()
            errors.append(f"dashboard inline script #{script_index}: {detail}")
    if script_index == 0:
        errors.append("dashboard.html contains no inline JavaScript to validate")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="repository root (defaults to the parent of scripts/ops)",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    errors = check_markdown_links(root)

    node = shutil.which("node")
    if node is None:
        errors.append("Node.js is required to syntax-check inline dashboard JavaScript")
    else:
        errors.extend(check_dashboard_scripts(root, node))

    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("Markdown links and dashboard JavaScript syntax are valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
