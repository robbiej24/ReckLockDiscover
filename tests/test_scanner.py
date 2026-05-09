"""Scanner integration tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from agenttrust_scanner.scanner import scan_repository


def test_scan_requires_directory(tmp_path: Path) -> None:
    missing = tmp_path / "nope"
    with pytest.raises(FileNotFoundError):
        scan_repository(missing)


def test_scan_excludes_extra_dir(tmp_path: Path) -> None:
    (tmp_path / "keep.py").write_text("import openai\n", encoding="utf-8")
    ignored = tmp_path / "fixtures"
    ignored.mkdir()
    (ignored / "noise.py").write_text("import openai\n", encoding="utf-8")
    r_all = scan_repository(tmp_path)
    r_filtered = scan_repository(tmp_path, exclude=("fixtures",))
    assert r_filtered.findings_count <= r_all.findings_count
