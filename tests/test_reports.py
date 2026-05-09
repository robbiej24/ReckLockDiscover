"""JSON & Markdown report tests."""

from __future__ import annotations

import json
from pathlib import Path

from recklock_scanner.report import render_markdown_report, write_reports
from recklock_scanner.scanner import scan_repository


def _populated_report(tmp_path: Path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "agent.py").write_text(
        "import openai\nimport langchain\nfrom anthropic import Anthropic\ntool_calls = []\n",
        encoding="utf-8",
    )
    deploy = tmp_path / "deploy.sh"
    deploy.write_text(
        "#!/bin/bash\nkubectl apply -f infra.yml\nexport AWS_SECRET_ACCESS_KEY=longverysecretvalue1234567890\n",
        encoding="utf-8",
    )
    return scan_repository(tmp_path)


def test_json_report_round_trips(tmp_path: Path) -> None:
    rpt = _populated_report(tmp_path / "repo")
    out = tmp_path / "out"
    out.mkdir()
    json_path, md_path = write_reports(rpt, out)

    parsed = json.loads(json_path.read_text(encoding="utf-8"))
    assert parsed["scanner"] == "recklock-discover"
    assert parsed["findings_count"] == rpt.findings_count
    assert "findings" in parsed
    for f in parsed["findings"]:
        for s in f["signals"]:
            snippet = s.get("redacted_snippet") or ""
            assert "AWS_SECRET_ACCESS_KEY=long" not in snippet


def test_markdown_report_includes_key_sections(tmp_path: Path) -> None:
    rpt = _populated_report(tmp_path / "repo")
    md = render_markdown_report(rpt)
    assert "# ReckLock Discover Report" in md
    assert "## Scan Summary" in md
    assert "### Findings by risk" in md
    assert "## Critical Findings" in md
    assert "## High-Risk Findings" in md
    assert "## AI Agent Candidates" in md
    assert "## Deployment Workflows" in md
    assert "## Financial/Payment Workflows" in md
    assert "## Suggested Governance Targets" in md
    assert "## Suggested ReckLock Registry Candidates" in md
    assert "## All findings" in md


def test_markdown_report_handles_empty_repo(tmp_path: Path) -> None:
    rpt = scan_repository(tmp_path)
    md = render_markdown_report(rpt)
    assert "# ReckLock Discover Report" in md
    assert "No automation, agents, or sensitive workflows were detected" in md


def test_summary_counts_match_findings(tmp_path: Path) -> None:
    rpt = _populated_report(tmp_path / "repo")
    total_by_risk = sum(rpt.findings_by_risk.values())
    total_by_action = sum(rpt.findings_by_action.values())
    assert total_by_risk == rpt.findings_count
    assert total_by_action == rpt.findings_count
