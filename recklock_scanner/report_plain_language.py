"""Plain-language narratives for Markdown scan reports (human-readable finding IDs)."""

from __future__ import annotations

from recklock_scanner.manifest_export import EXPORTABLE_ACTIONS
from recklock_scanner.models import FindingType, RecommendedAction, ScannerFinding, ScannerReport

_FINDING_TYPE_ROLE: dict[FindingType, str] = {
    "ai_agent": "Looks like an AI agent or assistant loop (models, tools, or agent frameworks).",
    "llm_tool": "Uses an LLM API, SDK, or orchestration library — model calls & related tooling.",
    "automation_agent": "Automation that may act on behalf of users or systems.",
    "outbound_agent": "Automation that reaches outbound to external services or networks.",
    "browser_agent": "Browser-driven or UI automation.",
    "scheduled_job": "Runs on a schedule (for example cron or a scheduled CI job).",
    "ci_cd_workflow": "Continuous integration or test automation in a pipeline definition.",
    "deployment_workflow": "Deploys or mutates infrastructure or runtime environments.",
    "database_writer": "Writes to a database or persistent store.",
    "payment_or_financial_workflow": "Touches payments, banking, ledgers, or money-movement APIs.",
    "secret_using_workflow": "Handles secrets, tokens, or credential material.",
    "shell_execution_workflow": "Runs shell commands or subprocesses.",
    "unknown": "Automation-related signals that did not map cleanly to a single category.",
}


def _role_sentence(finding_type: FindingType, display_name: str) -> str:
    base = _FINDING_TYPE_ROLE.get(
        finding_type,
        "Automation or sensitive workflow surface detected by static signals.",
    )
    return f"{base} Label on disk: **{display_name}**."


def _risk_sentence(risk_level: str, confidence: str, finding_type: FindingType) -> str:
    parts = []
    if risk_level == "critical":
        parts.append(
            "Rated **critical** because the combined signals suggest high blast radius "
            "(for example money movement, production deploys, secrets, or privileged access)."
        )
    elif risk_level == "high":
        parts.append(
            "Rated **high** — meaningful exposure if behavior or access is broader than intended."
        )
    elif risk_level == "medium":
        parts.append("Rated **medium** — worth tracking; impact depends on how it is wired in production.")
    else:
        parts.append("Rated **low** from this file alone — still verify in context.")

    parts.append(f"Classifier confidence is **{confidence}** (based on signal count & diversity).")
    if finding_type == "unknown":
        parts.append("Type is **unknown**, so human context matters more than the score.")
    return " ".join(parts)


def _action_sentence(action: RecommendedAction) -> str:
    if action == "govern":
        return (
            "**Govern** — treat as priority automation: assign ownership, approvals, & guardrails "
            "before you lean on catalog entries alone. Draft manifests may still export for inventory."
        )
    if action == "register":
        return (
            "**Register** — strong fit to document in the ReckLock Registry after a quick human sanity check "
            "(ownership, capabilities, & data scope)."
        )
    if action == "manual_review":
        return (
            "**Manual review** — risk looks serious but the match is fuzzy or low-confidence; "
            "a person should confirm whether this is real production automation before Registry work."
        )
    return (
        "**Monitor** — keep in operational/security review cadence; Registry is optional unless "
        "you want a public or compliance-facing catalog entry for this surface."
    )


def plain_language_finding_blurb(f: ScannerFinding) -> tuple[str, str, str, str]:
    """Return (role, risk, stance, capabilities_line) for Markdown."""
    role = _role_sentence(f.finding_type, f.name)
    risk = _risk_sentence(f.risk_level, f.confidence, f.finding_type)
    stance = _action_sentence(f.recommended_action)
    caps = f.likely_capabilities
    scopes = f.likely_permission_scopes
    cap_bits = []
    if caps:
        cap_bits.append("Inferred capabilities: " + ", ".join(f"`{c}`" for c in caps) + ".")
    if scopes:
        cap_bits.append("Inferred permission scopes: " + ", ".join(f"`{p}`" for p in scopes) + ".")
    capabilities_line = " ".join(cap_bits) if cap_bits else ""
    return role, risk, stance, capabilities_line


def render_plain_language_findings_section(findings: list[ScannerFinding]) -> list[str]:
    """Markdown section: one human-readable block per finding."""
    lines = [
        "## Plain-language guide to each finding",
        "",
        "_Each `find_…` id below is the same row you will see later in this file — "
        "spelled out here so you do not have to decode identifiers by memory._",
        "",
    ]
    if not findings:
        lines.extend(["_No findings in this scan._", ""])
        return lines

    for idx, f in enumerate(findings, start=1):
        role, risk, stance, caps_line = plain_language_finding_blurb(f)
        lines.append(f"{idx}. **`{f.finding_id}`** — `{f.path}`")
        lines.append(f"   - **What we think it is:** {role}")
        if caps_line:
            lines.append(f"   - **Detail:** {caps_line}")
        lines.append(f"   - **Why it is flagged:** {risk}")
        lines.append(f"   - **Recommended stance:** {stance}")
        lines.append(
            f"   - **Scanner note:** _{f.rationale}_"
        )
        lines.append("")
    return lines


def render_registry_guidance_section(report: ScannerReport) -> list[str]:
    """Explain Registry adds vs intentional exclusions for this scan."""
    findings = report.findings
    reg_primary = [f for f in findings if f.recommended_action in ("register", "manual_review")]
    govern_exportable = [f for f in findings if f.recommended_action == "govern"]
    monitor_only = [f for f in findings if f.recommended_action == "monitor"]
    export_count = sum(1 for f in findings if f.recommended_action in EXPORTABLE_ACTIONS)

    lines = [
        "## Registry fit for this scan (plain English)",
        "",
        "The ReckLock Registry is meant for **clear ownership & disclosure** of agents & sensitive automation — "
        "not every line of CI deserves a catalog entry.",
        "",
    ]

    lines.extend(
        [
            "### Who belongs in the Registry (recommended next step)",
            "",
        ]
    )
    if reg_primary:
        lines.extend(
            [
                "These rows are tagged **register** or **manual_review**. "
                "They are the best documentation targets: material automation with patterns that match known agent, "
                "deploy, finance, or secret-handling shapes — after you confirm they are real & current.",
                "",
            ]
        )
        for f in reg_primary:
            why = (
                "**Register** — publish capabilities & risk posture for partners or compliance."
                if f.recommended_action == "register"
                else "**Manual review** — confirm the match, then add if it is real operational automation."
            )
            lines.append(f"- **`{f.finding_id}`** (`{f.path}`): {why}")
        lines.append("")
    else:
        lines.extend(["_None tagged for Register-first follow-up in this run._", ""])

    lines.extend(
        [
            "### Manifest export vs. governance priority",
            "",
        ]
    )
    if govern_exportable:
        lines.extend(
            [
                f"This scan has **{len(govern_exportable)}** finding(s) tagged **govern**. "
                f"`recklock-discover … --export-manifests` can still emit drafts for them "
                f"(**{export_count}** exportable rows total including govern) — "
                "but the point is **policy & control first**: ownership, change management, & blast-radius limits "
                "before you treat the YAML as done.",
                "",
            ]
        )
        for f in govern_exportable:
            lines.append(
                f"- **`{f.finding_id}`** (`{f.path}`): critical-risk surface — stabilize governance, "
                "then decide if a Registry entry adds value."
            )
        lines.append("")
    else:
        lines.extend(
            [
                "_No govern-tagged rows — nothing in this run forced a policy-before-catalog split._",
                "",
            ]
        )

    lines.extend(
        [
            "### Who you can reasonably leave out (for now)",
            "",
        ]
    )
    if monitor_only:
        lines.extend(
            [
                f"**{len(monitor_only)}** finding(s) are tagged **monitor**. "
                "They are usually routine pipelines, lower-confidence matches, or medium-risk surfaces where "
                "watching them in normal engineering reviews is enough unless you explicitly want a catalog entry.",
                "",
            ]
        )
        for f in monitor_only:
            lines.append(
                f"- **`{f.finding_id}`** (`{f.path}`): keep on dashboards or PR review — "
                "skip Registry unless you need external visibility."
            )
        lines.append("")
    else:
        lines.extend(["_No monitor-only rows._", ""])

    lines.extend(
        [
            "### Why not everything is a Registry row",
            "",
            "Registry entries work best when **identity, capabilities, & ownership** are stable. "
            "Test fixtures, scanner source that merely mentions payments or deploy verbs, & noisy CI jobs "
            "often fail that test — governing or monitoring them is still useful even when you skip the catalog.",
            "",
        ]
    )
    return lines
