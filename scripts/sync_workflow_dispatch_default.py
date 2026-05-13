#!/usr/bin/env python3
"""Set recklock_release workflow_dispatch default to v{SCANNER_VERSION} in both stock workflows."""

from __future__ import annotations

import re
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[5]
_DISCOVER_ROOT = Path(__file__).resolve().parents[1]
_CONSTANTS = _DISCOVER_ROOT / "recklock_scanner" / "constants.py"
_WORKFLOWS = (
    _REPO_ROOT / ".github" / "workflows" / "recklock-discover.yml",
    _DISCOVER_ROOT / ".github" / "workflows" / "recklock-discover.yml",
)

_VAR_RE = re.compile(r'^SCANNER_VERSION = "([^"]+)"\s*$', re.MULTILINE)
# Single workflow_dispatch input default shaped like `default: v1.2.3` (Discover release tags).
_DEFAULT_LINE_RE = re.compile(r"^(\s*default:\s+)v[\d.]+\s*$", re.MULTILINE)


def _scanner_version() -> str:
    raw = _CONSTANTS.read_text(encoding="utf-8")
    match = _VAR_RE.search(raw)
    if not match:
        raise SystemExit(f"Could not parse SCANNER_VERSION from {_CONSTANTS}")
    return match.group(1)


def _patch_body(body: str, tag: str) -> str:
    if len(_DEFAULT_LINE_RE.findall(body)) != 1:
        raise SystemExit(
            "Expected exactly one `default: v…` line in workflow file (recklock_release input)."
        )
    return _DEFAULT_LINE_RE.sub(rf"\g<1>{tag}", body, count=1)


def main() -> int:
    ver = _scanner_version()
    tag = f"v{ver}"
    for wf in _WORKFLOWS:
        if not wf.is_file():
            print(f"skip missing {wf}", file=sys.stderr)
            continue
        old = wf.read_text(encoding="utf-8")
        new = _patch_body(old, tag)
        if new != old:
            wf.write_text(new, encoding="utf-8")
            print(f"updated {wf.relative_to(_REPO_ROOT)} → default {tag}")
        else:
            print(f"ok {wf.relative_to(_REPO_ROOT)} (already {tag})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
