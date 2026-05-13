"""JSON & Markdown reporting for ReckLock Discover."""

from __future__ import annotations

import json
from pathlib import Path

from recklock_scanner.constants import (
    DEFAULT_DETAILS_MARKDOWN_FILENAME,
    DEFAULT_JSON_FILENAME,
    DEFAULT_SUMMARY_MARKDOWN_FILENAME,
)
from recklock_scanner.models import ScannerFinding, ScannerReport
from recklock_scanner.registry_prompts import registry_candidate_count
from recklock_scanner.report_plain_language import (
    render_plain_language_findings_section,
    render_registry_guidance_section,
)


def write_json_report(report: ScannerReport, out_path: Path) -> Path:
    """Write the report as pretty-printed JSON."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = report.model_dump(mode="json")
    out_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return out_path


def _by_id(findings: list[ScannerFinding]) -> dict[str, ScannerFinding]:
    return {f.finding_id: f for f in findings}


def _priority_counts(report: ScannerReport) -> tuple[int, int, int]:
    """Critical + high findings, registry-ready count, total findings."""
    crit_high = sum(
        1 for f in report.findings if f.risk_level in ("critical", "high")
    )
    reg_ready = registry_candidate_count(report)
    return crit_high, reg_ready, report.findings_count


def _md_read_this_first(
    report: ScannerReport,
    *,
    json_name: str,
    details_md_name: str,
    summary_md_name: str,
) -> list[str]:
    crit_high, reg_ready, total = _priority_counts(report)
    lines = [
        "## Executive overview (~10 seconds)",
        "",
        "| Priority | Do this |",
        "| --- | --- |",
        f"| **Totals** | **{total}** findings in this scan |",
    ]
    if crit_high:
        lines.append(
            f"| **Risk** | Review **{crit_high}** critical/high items → "
            "[Critical Findings](#critical-findings) & [High-Risk Findings](#high-risk-findings) |"
        )
    else:
        lines.append("| **Risk** | No critical/high findings — skim [AI Agent Candidates](#ai-agent-candidates) if relevant |")

    if reg_ready:
        lines.append(
            f"| **Registry** | **{reg_ready}** manifest-ready finding(s) — run "
            "`recklock-discover scan <repo> --export-manifests` (see [Registry candidates](#suggested-recklock-registry-candidates)) |"
        )
    else:
        lines.append("| **Registry** | Nothing flagged for Registry export this run |")

    lines.extend(
        [
            f"| **Files** | Machine-readable: `{json_name}` · **Summary of findings:** `{summary_md_name}` · "
            f"**Details of findings:** `{details_md_name}` |",
            "",
            "_Heuristic scan — verify before acting._",
            "",
            "---",
            "",
        ]
    )
    return lines


def render_summary_of_findings_markdown(report: ScannerReport, *, output_dir: Path) -> str:
    """Short executive summary for humans (≈10 seconds)."""
    crit_high, reg_ready, total = _priority_counts(report)
    scanned = report.scanned_path
    root = Path(scanned).resolve()
    out = output_dir.resolve()

    lines = [
        "# Summary of findings",
        "",
        "_ReckLock Discover — quick read. See **Details of findings** for full evidence._",
        "",
        f"- **Scanned:** `{scanned}`",
        f"- **Findings:** {total} (critical/high: **{crit_high}**, Registry-ready: **{reg_ready}**)",
        "",
        "## What to do next",
        "",
    ]
    if crit_high:
        lines.append(
            f"1. **Risk** — open **Details of findings** (`{DEFAULT_DETAILS_MARKDOWN_FILENAME}`) → Critical & High sections."
        )
    else:
        lines.append("1. **Skim** — open details only if you care about agents, CI/CD, or finance workflows.")

    if reg_ready:
        lines.append(
            "2. **Registry** — export draft manifests (review YAML before commit):"
        )
        lines.extend(
            [
                "",
                "```bash",
                f'recklock-discover scan "{root}" --output-dir "{out}" --export-manifests',
                "```",
                "",
            ]
        )
    else:
        lines.append("2. **Registry** — nothing queued for manifest export this run.")

    lines.extend(
        [
            f"3. **Evidence** — per-file depth lives in `{DEFAULT_DETAILS_MARKDOWN_FILENAME}` (section **All findings**).",
            "",
            "---",
            "",
            "_Static analysis only — not proof of runtime behavior._",
            "",
        ]
    )
    return "\n".join(lines)


def _md_header(report: ScannerReport) -> list[str]:
    return [
        "# ReckLock Discover Report",
        "",
        "## Scan Summary",
        "",
        f"- **Scanner version:** `{report.scanner_version}`",
        f"- **Scanned path:** `{report.scanned_path}`",
        f"- **Scanned at:** `{report.scanned_at}`",
        f"- **Files scanned:** {report.files_scanned}",
        f"- **Files with findings:** {report.files_matched}",
        f"- **Total findings:** {report.findings_count}",
        "",
    ]


def _md_summary_table(title: str, mapping: dict[str, int]) -> list[str]:
    if not mapping:
        return []
    lines = [f"### {title}", "", "| Bucket | Count |", "| --- | --- |"]
    for k in sorted(mapping):
        lines.append(f"| `{k}` | {mapping[k]} |")
    lines.append("")
    return lines


def _brief_lines(title: str, findings: list[ScannerFinding], empty_msg: str) -> list[str]:
    lines = [f"## {title}", ""]
    if not findings:
        lines.extend([empty_msg, ""])
        return lines
    for f in findings:
        lines.append(
            f"- `{f.path}` — **{f.finding_type}** "
            f"({f.risk_level}, {f.confidence}) → `{f.recommended_action}` "
            f"(`{f.finding_id}`)"
        )
    lines.append("")
    return lines


def _md_id_section(
    title: str,
    ids: list[str],
    findings: list[ScannerFinding],
    blurb: str,
    *,
    empty_blurb: str = "_None._",
) -> list[str]:
    by_id = _by_id(findings)
    lines = [f"## {title}", "", blurb, ""]
    if not ids:
        lines.extend([empty_blurb, ""])
        return lines
    for fid in ids:
        f = by_id.get(fid)
        if not f:
            continue
        lines.append(
            f"- `{f.path}` — **{f.finding_type}** ({f.risk_level}) → `{f.recommended_action}` (`{f.finding_id}`)"
        )
    lines.append("")
    return lines


def _md_finding_block(f: ScannerFinding) -> list[str]:
    sig_lines: list[str] = []
    for s in f.signals:
        loc = f"line {s.line_number}" if s.line_number else "filename match"
        snip = s.redacted_snippet or ""
        snip_md = f" — `{snip}`" if snip else ""
        sig_lines.append(f"  - **{s.name}** ({s.category}, {loc}){snip_md}")

    return [
        f"### `{f.path}` — {f.name}",
        "",
        f"- finding_id: `{f.finding_id}`",
        f"- finding_type: `{f.finding_type}`",
        f"- risk_level: **{f.risk_level}**",
        f"- confidence: `{f.confidence}`",
        f"- recommended_action: **{f.recommended_action}**",
        f"- likely_capabilities: {', '.join(f'`{c}`' for c in f.likely_capabilities) or '—'}",
        f"- likely_permission_scopes: {', '.join(f'`{p}`' for p in f.likely_permission_scopes) or '—'}",
        f"- rationale: _{f.rationale}_",
        "- signals:",
        *sig_lines,
        "",
    ]


def render_markdown_report(
    report: ScannerReport,
    *,
    json_filename: str = DEFAULT_JSON_FILENAME,
    details_markdown_filename: str = DEFAULT_DETAILS_MARKDOWN_FILENAME,
    summary_markdown_filename: str = DEFAULT_SUMMARY_MARKDOWN_FILENAME,
) -> str:
    """Render Markdown suitable for GitHub issues, PRs, or docs."""
    parts: list[str] = []
    parts.append("# Details of findings")
    parts.append("")
    parts.append("_ReckLock Discover — full narrative & evidence._")
    parts.append("")
    parts.extend(
        _md_read_this_first(
            report,
            json_name=json_filename,
            details_md_name=details_markdown_filename,
            summary_md_name=summary_markdown_filename,
        )
    )
    parts.extend(render_plain_language_findings_section(report.findings))
    parts.extend(render_registry_guidance_section(report))
    parts.extend(_md_header(report)[2:])  # skip duplicate H1 + blank (already added)

    parts.extend(_md_summary_table("Findings by type", report.findings_by_type))
    parts.extend(_md_summary_table("Findings by risk", report.findings_by_risk))
    parts.extend(_md_summary_table("Findings by recommended action", report.findings_by_action))

    critical = [f for f in report.findings if f.risk_level == "critical"]
    high = [f for f in report.findings if f.risk_level == "high"]
    ai_candidates = [f for f in report.findings if f.finding_type in ("ai_agent", "llm_tool")]
    deploy = [
        f for f in report.findings if f.finding_type in ("deployment_workflow", "ci_cd_workflow", "scheduled_job")
    ]
    financial = [f for f in report.findings if f.finding_type == "payment_or_financial_workflow"]

    parts.extend(
        _brief_lines(
            "Critical Findings",
            critical,
            "_No critical-risk findings._",
        )
    )
    parts.extend(
        _brief_lines(
            "High-Risk Findings",
            high,
            "_No high-risk findings._",
        )
    )
    parts.extend(
        _brief_lines(
            "AI Agent Candidates",
            ai_candidates,
            "_No dedicated AI agent or LLM tool surfaces detected._",
        )
    )
    parts.extend(
        _brief_lines(
            "Deployment Workflows",
            deploy,
            "_No CI/CD or deployment workflow surfaces detected._",
        )
    )
    parts.extend(
        _brief_lines(
            "Financial/Payment Workflows",
            financial,
            "_No payment or banking workflow surfaces detected._",
        )
    )

    registry_ids = [f.finding_id for f in report.findings if f.recommended_action in ("register", "manual_review")]

    parts.extend(
        _md_id_section(
            "Suggested Governance Targets",
            report.recommended_governance_targets,
            report.findings,
            "_Critical-risk automation that likely needs strict governance first._",
        )
    )
    parts.extend(
        _md_id_section(
            "Suggested ReckLock Registry Candidates",
            registry_ids,
            report.findings,
            "_Findings tagged **register** or **manual_review** — strong registry candidates after review._",
        )
    )

    parts.append("## All findings")
    parts.append("")
    if not report.findings:
        parts.append("_No automation, agents, or sensitive workflows were detected._")
        parts.append("")
    else:
        parts.append(
            "<details>\n\n"
            "<summary><strong>Full per-file evidence (collapsed — open when you need depth)</strong></summary>\n\n"
        )
        parts.append("")
        for f in report.findings:
            parts.extend(_md_finding_block(f))
        parts.append("")
        parts.append("</details>")
        parts.append("")

    parts.append("---")
    parts.append("")
    parts.append(
        "_ReckLock Discover uses deterministic static analysis. Findings are educated guesses, "
        "not proof of behavior. Review high-risk paths manually before acting._"
    )
    parts.append("")
    return "\n".join(parts)


def write_markdown_report(
    report: ScannerReport,
    out_path: Path,
    *,
    json_filename: str = DEFAULT_JSON_FILENAME,
) -> Path:
    """Write a Markdown view of *report*."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    body = render_markdown_report(
        report,
        json_filename=json_filename,
        details_markdown_filename=out_path.name,
        summary_markdown_filename=DEFAULT_SUMMARY_MARKDOWN_FILENAME,
    )
    out_path.write_text(body, encoding="utf-8")
    return out_path


def write_summary_of_findings_report(report: ScannerReport, out_path: Path) -> Path:
    """Executive summary Markdown — open first in CI artifacts."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        render_summary_of_findings_markdown(report, output_dir=out_path.parent),
        encoding="utf-8",
    )
    return out_path


def write_reports(
    report: ScannerReport,
    output_dir: Path,
    *,
    json_filename: str = DEFAULT_JSON_FILENAME,
    details_markdown_filename: str = DEFAULT_DETAILS_MARKDOWN_FILENAME,
    summary_markdown_filename: str = DEFAULT_SUMMARY_MARKDOWN_FILENAME,
) -> tuple[Path, Path, Path]:
    """Write JSON, summary Markdown, & details Markdown into *output_dir*."""
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = write_json_report(report, output_dir / json_filename)
    summary_path = write_summary_of_findings_report(report, output_dir / summary_markdown_filename)
    details_path = write_markdown_report(
        report,
        output_dir / details_markdown_filename,
        json_filename=json_filename,
    )
    return json_path, summary_path, details_path
