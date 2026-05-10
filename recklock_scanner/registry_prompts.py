"""Shared copy for ReckLock Registry follow-up after discovery."""

from __future__ import annotations

from pathlib import Path

from recklock_scanner.manifest_export import EXPORTABLE_ACTIONS
from recklock_scanner.models import ScannerReport


def registry_candidate_count(report: ScannerReport) -> int:
    """Count findings that can become ReckLock Registry manifest drafts."""
    return sum(1 for finding in report.findings if finding.recommended_action in EXPORTABLE_ACTIONS)


def registry_opt_in_prompt(count: int) -> str:
    plural = "" if count == 1 else "s"
    return (
        f"ReckLock Discover found {count} AI agent{plural}. Add them to your ReckLock Registry so you can display:\n\n"
        "- That you own them\n"
        "- What their capabilities are\n"
        "- Which risks they carry &\n"
        "- Allow other people who want to license your agents to contact you?"
    )


def registry_cli_commands(scanned_path: Path, output_dir: Path | None) -> str:
    """Concrete next-step commands for humans & CI logs."""
    root = Path(scanned_path).resolve()
    out = output_dir.resolve() if output_dir else Path.cwd().resolve()
    return (
        "Next step — export draft Registry manifests (review before commit):\n\n"
        f'  recklock-discover scan "{root}" --output-dir "{out}" --export-manifests\n\n'
        "Or answer yes when prompted locally, or pass --add-to-registry for the same export.\n"
        "Manifests default to "
        f'`{out}/recklock_manifest_exports/` (YAML drafts for human review).'
    )
