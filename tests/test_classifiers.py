"""Classifier behavior tests."""

from __future__ import annotations

from recklock_scanner.classifiers import classify_finding
from recklock_scanner.models import ScannerSignal


def test_workflow_file_becomes_ci_cd_not_unknown() -> None:
    signals = [
        ScannerSignal(
            name="GitHub Actions workflow file",
            category="ci_cd",
            line_number=None,
            redacted_snippet=None,
        ),
    ]
    f = classify_finding(
        finding_id="find_x",
        name="Ci",
        path=".github/workflows/ci.yml",
        rel_posix=".github/workflows/ci.yml",
        lower_name="ci.yml",
        signals=signals,
    )
    assert f.finding_type == "ci_cd_workflow"


def test_llm_with_tools_becomes_ai_agent() -> None:
    signals = [
        ScannerSignal(name="imports or calls OpenAI", category="llm_ai", line_number=1),
        ScannerSignal(name="tool calling / function calling", category="llm_ai", line_number=2),
    ]
    f = classify_finding(
        finding_id="find_y",
        name="Agent",
        path="agent.py",
        rel_posix="agent.py",
        lower_name="agent.py",
        signals=signals,
    )
    assert f.finding_type == "ai_agent"
    assert f.risk_level in {"high", "critical", "medium"}
