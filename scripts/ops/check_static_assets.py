from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections.abc import Iterator
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote

_FENCED_BLOCK = re.compile(r"^ {0,3}(`{3,}|~{3,})")
_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")
_EXCLUDED_DIRS = {".git", ".venv", "__pycache__", "node_modules", "site-packages"}


def _mask(source: str, start: int, end: int) -> str:
    return "".join("\n" if char == "\n" else " " for char in source[start:end])


def strip_markdown_code(source: str) -> str:
    """Mask fenced and inline code while preserving offsets and line numbers."""
    lines = source.splitlines(keepends=True)
    output: list[str] = []
    offset = 0
    fence_char: str | None = None
    fence_length = 0

    for line in lines:
        match = _FENCED_BLOCK.match(line)
        if fence_char is None and match:
            marker = match.group(1)
            fence_char = marker[0]
            fence_length = len(marker)
            output.append(_mask(source, offset, offset + len(line)))
        elif fence_char is not None:
            marker_match = re.match(r"^ {0,3}(" + re.escape(fence_char) + r"{"
                                    + str(fence_length) + r",})\s*$", line.rstrip("\r\n"))
            output.append(_mask(source, offset, offset + len(line)))
            if marker_match:
                fence_char = None
                fence_length = 0
        else:
            output.append(line)
        offset += len(line)

    without_fences = "".join(output)
    inline_code = re.compile(r"(?<!`)(`+)(?!`)([\s\S]*?)(?<!`)\1(?!`)")
    return inline_code.sub(
        lambda match: _mask(match.group(0), 0, len(match.group(0))),
        without_fences,
    )


def _is_escaped(source: str, index: int) -> bool:
    backslashes = 0
    position = index - 1
    while position >= 0 and source[position] == "\\":
        backslashes += 1
        position -= 1
    return backslashes % 2 == 1


def iter_markdown_destinations(source: str) -> Iterator[tuple[str, int]]:
    """Yield (destination, line) pairs from inline Markdown links and images."""
    masked = strip_markdown_code(source)
    index = 0
    while index < len(masked) - 1:
        if masked[index] != "]" or masked[index + 1] != "(" or _is_escaped(masked, index):
            index += 1
            continue

        position = index + 2
        while position < len(masked) and masked[position].isspace():
            position += 1

        destination: list[str] = []
        if position < len(masked) and masked[position] == "<":
            position += 1
            while position < len(masked) and masked[position] != ">":
                if masked[position] == "\\" and position + 1 < len(masked):
                    position += 1
                destination.append(source[position])
                position += 1
            if position < len(masked):
                position += 1
        else:
            depth = 0
            while position < len(masked):
                char = masked[position]
                if char == "\\" and position + 1 < len(masked):
                    position += 1
                    destination.append(source[position])
                elif char == "(":
                    depth += 1
                    destination.append(char)
                elif char == ")":
                    if depth == 0:
                        break
                    depth -= 1
                    destination.append(char)
                elif char.isspace() and depth == 0:
                    break
                else:
                    destination.append(char)
                position += 1

        target = "".join(destination).strip()
        if target:
            line = source.count("\n", 0, index) + 1
            yield target, line
        index = max(position, index + 2)


def resolve_local_target(root: Path, source_file: Path, destination: str) -> Path | None:
    """Resolve a relative or repository-root Markdown destination; ignore external URLs."""
    destination = destination.strip()
    if not destination or destination.startswith(("#", "//")):
        return None
    if _SCHEME.match(destination):
        return None

    path_part = destination.split("#", 1)[0].split("?", 1)[0]
    if not path_part:
        return None
    path_part = unquote(path_part.replace("\\", "/"))
    if path_part.startswith("/"):
        return root / path_part.lstrip("/")
    return source_file.parent / path_part


def check_markdown_links(root: Path) -> tuple[int, list[str]]:
    markdown_files = sorted(
        path for path in root.rglob("*.md")
        if not any(part in _EXCLUDED_DIRS for part in path.relative_to(root).parts)
    )
    errors: list[str] = []
    for source_file in markdown_files:
        try:
            source = source_file.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            errors.append(f"{source_file.relative_to(root)}: cannot read Markdown: {exc}")
            continue

        for destination, line in iter_markdown_destinations(source):
            target = resolve_local_target(root, source_file, destination)
            if target is not None and not target.exists():
                relative_source = source_file.relative_to(root)
                errors.append(
                    f"{relative_source}:{line}: broken relative link {destination!r}"
                )
    return len(markdown_files), errors


class _InlineScriptParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.scripts: list[tuple[str, str]] = []
        self._current: list[str] | None = None
        self._module = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "script":
            return
        attributes = dict(attrs)
        script_type = (attributes.get("type") or "").lower()
        is_javascript = script_type in {"", "text/javascript", "application/javascript", "module"}
        if "src" in attributes or not is_javascript:
            self._current = None
            return
        self._current = []
        self._module = script_type == "module"

    def handle_data(self, data: str) -> None:
        if self._current is not None:
            self._current.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self._current is not None:
            self.scripts.append(("".join(self._current), "module" if self._module else "script"))
            self._current = None
            self._module = False


def extract_inline_javascript(html: str) -> list[tuple[str, str]]:
    parser = _InlineScriptParser()
    parser.feed(html)
    parser.close()
    return parser.scripts


def check_dashboard_javascript(root: Path) -> tuple[int, list[str]]:
    dashboard = root / "backend" / "openshield" / "dashboard.html"
    try:
        html = dashboard.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return 0, [f"cannot read {dashboard}: {exc}"]

    scripts = extract_inline_javascript(html)
    if not scripts:
        return 0, ["dashboard.html: no inline JavaScript blocks found"]

    errors: list[str] = []
    for index, (script, script_kind) in enumerate(scripts, start=1):
        command = ["node", "--check", "-"]
        if script_kind == "module":
            command = ["node", "--input-type=module", "--check"]
        try:
            result = subprocess.run(
                command,
                input=script,
                text=True,
                capture_output=True,
                check=False,
                cwd=root,
            )
        except FileNotFoundError:
            return len(scripts), ["Node.js is required for dashboard JavaScript syntax checks"]
        if result.returncode:
            detail = (result.stderr or result.stdout).strip()
            errors.append(f"dashboard.html: inline script {index} failed node --check:\n{detail}")
    return len(scripts), errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate repository-relative Markdown links and dashboard JavaScript syntax."
    )
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    root = args.root.resolve()

    markdown_count, markdown_errors = check_markdown_links(root)
    script_count, script_errors = check_dashboard_javascript(root)
    errors = markdown_errors + script_errors

    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1

    print(
        f"Static checks passed: {markdown_count} Markdown files; "
        f"{script_count} inline dashboard JavaScript block(s)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
