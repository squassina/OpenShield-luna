from __future__ import annotations

import importlib.util
from pathlib import Path

_MODULE_PATH = next(
    parent / "scripts" / "ops" / "check_static_assets.py"
    for parent in Path(__file__).resolve().parents
    if (parent / "scripts" / "ops" / "check_static_assets.py").is_file()
)
_SPEC = importlib.util.spec_from_file_location("check_static_assets", _MODULE_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_STATIC_CHECKS = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_STATIC_CHECKS)


def test_markdown_scanner_finds_links_and_images_but_ignores_code() -> None:
    markdown = """[guide](docs/guide.md)
![diagram](images/topology.svg)
[external](https://example.com/docs)
`[inline](missing-inline.md)`

```markdown
[code sample](missing-fenced.md)
```
"""
    destinations = list(_STATIC_CHECKS.iter_markdown_destinations(markdown))

    assert destinations == [
        ("docs/guide.md", 1),
        ("images/topology.svg", 2),
        ("https://example.com/docs", 3),
    ]


def test_markdown_scanner_supports_angle_urls_and_balanced_parentheses() -> None:
    markdown = "[angle](<docs/guide with spaces.md>)\n[plot](images/flow_(v2).svg)"
    destinations = list(_STATIC_CHECKS.iter_markdown_destinations(markdown))

    assert destinations == [
        ("docs/guide with spaces.md", 1),
        ("images/flow_(v2).svg", 2),
    ]


def test_local_link_resolution_handles_relative_root_and_external_urls(
    tmp_path: Path,
) -> None:
    source = tmp_path / "docs" / "guide.md"
    source.parent.mkdir()
    expected_relative = tmp_path / "docs" / "next.md"
    expected_root = tmp_path / "README.md"

    assert _STATIC_CHECKS.resolve_local_target(
        tmp_path, source, "next.md#setup"
    ) == expected_relative
    assert _STATIC_CHECKS.resolve_local_target(
        tmp_path, source, "/README.md"
    ) == expected_root
    assert _STATIC_CHECKS.resolve_local_target(
        tmp_path, source, "https://example.com"
    ) is None
    assert _STATIC_CHECKS.resolve_local_target(
        tmp_path, source, "#section"
    ) is None


def test_inline_script_extractor_ignores_external_and_json_scripts() -> None:
    html = """<script>const answer = 42;</script>
<script src="/assets/app.js"></script>
<script type="application/json">{"enabled": true}</script>
<script type="module">export const ready = true;</script>
"""
    scripts = _STATIC_CHECKS.extract_inline_javascript(html)

    assert scripts == [
        ("const answer = 42;", "script"),
        ("export const ready = true;", "module"),
    ]


def test_markdown_code_masking_does_not_consume_links_after_unmatched_backticks() -> None:
    markdown = "An unmatched marker ` remains, then [valid](docs/guide.md)."
    assert list(_STATIC_CHECKS.iter_markdown_destinations(markdown)) == [
        ("docs/guide.md", 1)
    ]
