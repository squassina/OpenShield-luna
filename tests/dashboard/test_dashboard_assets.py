from __future__ import annotations

import re
from pathlib import Path

from html5lib.html5parser import HTMLParser


def dashboard_html() -> str:
    candidates = [
        Path(__file__).resolve().parents[2] / "backend" / "openshield" / "dashboard.html",
        Path("/app/openshield/dashboard.html"),
    ]
    path = next((item for item in candidates if item.is_file()), None)
    assert path is not None, "dashboard.html was not found in the test image"
    return path.read_text(encoding="utf-8")


def test_dashboard_html_has_no_parse_errors() -> None:
    parser = HTMLParser(strict=True)
    parser.parse(dashboard_html())


def test_dashboard_ids_are_unique_and_static_references_exist() -> None:
    source = dashboard_html()
    ids = re.findall(r'\bid=["\']([^"\']+)["\']', source)
    references = re.findall(r'\$\(\s*["\']([^"\']+)["\']\s*\)', source)

    duplicates = sorted({item for item in ids if ids.count(item) > 1})
    missing = sorted(set(references) - set(ids))

    assert not duplicates, f"Duplicate dashboard IDs: {duplicates}"
    assert not missing, f"Dashboard references missing IDs: {missing}"
