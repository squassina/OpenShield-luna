#!/usr/bin/env python3
"""Syntax-check inline JavaScript in the OpenShield dashboard with Node.js."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "backend" / "openshield" / "dashboard.html"


class InlineScriptParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.scripts: list[tuple[str, str]] = []
        self._active_type: str | None = None
        self._active_data: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "script":
            return
        attributes = dict(attrs)
        if attributes.get("src"):
            self._active_type = None
            return
        script_type = (attributes.get("type") or "text/javascript").split(";", 1)[0].strip().lower()
        if script_type not in {"text/javascript", "application/javascript", "module"}:
            self._active_type = None
            return
        self._active_type = script_type
        self._active_data = []

    def handle_data(self, data: str) -> None:
        if self._active_type is not None:
            self._active_data.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "script" or self._active_type is None:
            return
        self.scripts.append((self._active_type, "".join(self._active_data)))
        self._active_type = None
        self._active_data = []


def main() -> int:
    node = shutil.which("node")
    if node is None:
        print("node executable is required for dashboard JavaScript syntax validation.", file=sys.stderr)
        return 1

    parser = InlineScriptParser()
    parser.feed(DASHBOARD.read_text(encoding="utf-8"))
    checked = 0
    with tempfile.TemporaryDirectory(prefix="openshield-js-check-") as directory:
        temp_root = Path(directory)
        for index, (script_type, source) in enumerate(parser.scripts):
            if not source.strip():
                continue
            extension = ".mjs" if script_type == "module" else ".cjs"
            script_path = temp_root / f"inline-{index}{extension}"
            script_path.write_text(source, encoding="utf-8")
            result = subprocess.run(
                [node, "--check", str(script_path)],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode:
                print(f"Dashboard inline script {index} failed syntax validation:", file=sys.stderr)
                print(result.stderr or result.stdout, file=sys.stderr)
                return result.returncode
            checked += 1
    print(f"Validated syntax of {checked} inline dashboard JavaScript blocks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
