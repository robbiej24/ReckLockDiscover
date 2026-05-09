"""Typer CLI with Rich terminal output."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from agenttrust_scanner.constants import SCANNER_VERSION
from agenttrust_scanner.manifest_export import (
    DEFAULT_EXPORT_DIRNAME,
    EXPORTABLE_ACTIONS,
    export_manifests,
)
from agenttrust_scanner.models import Confidence, ScannerReport
from agenttrust_scanner.report import write_reports
from agenttrust_scanner.scanner import scan_repository

app = typer.Typer(
    name="recklock-discover",
    help=(
        "Find AI agents, automations, CI/CD workflows, deployment scripts, "
        "and sensitive execution paths in your codebase — offline & deterministic."
    ),
)

_console = Console(stderr=True)


ConfidenceOption = Literal["low", "medium", "high"]
OutputFormat = Literal["human", "json"]


def run_scan(
    path: Path,
    *,
    output_dir: Path | None = None,
    include: str | None = None,
    exclude: str | None = None,
    min_confidence: Confidence | None = None,
    export_manifests_flag: bool = False,
    manifest_export_dir: Path | None = None,
) -> tuple[ScannerReport, Path, Path, Path | None, list[tuple[Path, bool, str]]]:
    """Run a scan & write JSON/Markdown reports. Optionally export manifests."""
    report = scan_repository(
        path,
        include=include,
        exclude=exclude,
        min_confidence=min_confidence,
    )
    out_dir = (output_dir or Path.cwd()).resolve()
    json_path, md_path = write_reports(report, out_dir)

    manifest_dir: Path | None = None
    manifest_results: list[tuple[Path, bool, str]] = []
    if export_manifests_flag:
        manifest_dir = (manifest_export_dir or (out_dir / DEFAULT_EXPORT_DIRNAME)).resolve()
        manifest_results = export_manifests(
            report.findings,
            manifest_dir,
            scanner_version=SCANNER_VERSION,
            actions=EXPORTABLE_ACTIONS,
        )
    return report, json_path, md_path, manifest_dir, manifest_results


def report_to_json(report: ScannerReport) -> str:
    return json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True)


def print_rich_summary(report: ScannerReport) -> None:
    """Colored summary tables after a scan."""
    _console.print(f"[bold green]ReckLock Discover[/bold green] v{report.scanner_version}")
    _console.print(f"  [bold]Path[/bold]    {report.scanned_path}")
    _console.print(f"  [bold]When[/bold]    {report.scanned_at}")
    _console.print(f"  [bold]Files[/bold]   scanned={report.files_scanned}  with_findings={report.files_matched}")
    _console.print(f"  [bold]Findings[/bold] {report.findings_count}")

    if report.findings_by_risk:
        tbl = Table(title="By risk", show_header=True, header_style="bold")
        tbl.add_column("Level")
        tbl.add_column("Count", justify="right")
        for k in ("critical", "high", "medium", "low"):
            if report.findings_by_risk.get(k):
                tbl.add_row(k, str(report.findings_by_risk[k]))
        _console.print(tbl)

    if report.findings_by_action:
        tbl2 = Table(title="By recommended action", show_header=True, header_style="bold")
        tbl2.add_column("Action")
        tbl2.add_column("Count", justify="right")
        for k in ("govern", "register", "manual_review", "monitor"):
            if report.findings_by_action.get(k):
                tbl2.add_row(k, str(report.findings_by_action[k]))
        _console.print(tbl2)

    if report.recommended_governance_targets:
        _console.print(f"  [yellow]Govern first:[/yellow] {len(report.recommended_governance_targets)} candidate(s)")
    reg_eligible = sum(1 for f in report.findings if f.recommended_action in ("register", "manual_review"))
    if reg_eligible:
        _console.print(f"  [cyan]Registry candidates:[/cyan] {reg_eligible} finding(s)")


@app.command("scan")
def scan_command(
    path: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        help="Repository root to scan",
    ),
    output_dir: Path | None = typer.Option(
        None,
        "--output-dir",
        "-o",
        help="Directory for JSON/Markdown reports (default: current working directory)",
    ),
    export_manifests_flag: bool = typer.Option(
        False,
        "--export-manifests",
        help="Write unsigned ReckLock Registry manifest drafts for eligible findings",
    ),
    manifest_dir: Path | None = typer.Option(
        None,
        "--manifest-dir",
        help=f"Manifest export directory (default: <output-dir>/{DEFAULT_EXPORT_DIRNAME})",
    ),
    min_confidence: ConfidenceOption | None = typer.Option(
        None,
        "--min-confidence",
        help="Drop findings below this confidence: low | medium | high",
    ),
    include: str | None = typer.Option(
        None,
        "--include",
        help='Comma-separated globs, e.g. "*.py,*.ts,.github/workflows/*.yml"',
    ),
    exclude: str | None = typer.Option(
        None,
        "--exclude",
        help='Comma-separated extra excludes (dirs or globs), e.g. "fixtures,*.min.js"',
    ),
    output_format: OutputFormat = typer.Option(
        "human",
        "--format",
        "-f",
        help='Terminal output: "human" (default) or "json"',
    ),
) -> None:
    """Scan a repository for agents, automation, CI/CD, deploy scripts & sensitive workflows."""
    if min_confidence is not None and min_confidence not in {"low", "medium", "high"}:
        _console.print("[red]Invalid --min-confidence. Use: low | medium | high[/red]")
        raise typer.Exit(code=1)
    if output_format not in {"human", "json"}:
        _console.print("[red]Invalid --format. Use: human | json[/red]")
        raise typer.Exit(code=1)

    conf: Confidence | None = min_confidence  # type: ignore[assignment]

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
            console=_console,
        ) as progress:
            progress.add_task(description="Scanning repository…", total=None)
            report, json_path, md_path, manifest_export_dir, manifest_results = run_scan(
                path,
                output_dir=output_dir,
                include=include,
                exclude=exclude,
                min_confidence=conf,
                export_manifests_flag=export_manifests_flag,
                manifest_export_dir=manifest_dir,
            )
    except (FileNotFoundError, NotADirectoryError, OSError) as exc:
        _console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc

    if output_format == "json":
        typer.echo(report_to_json(report))
        return

    print_rich_summary(report)
    _console.print(f"  [dim]json_report[/dim]   {json_path}")
    _console.print(f"  [dim]md_report[/dim]     {md_path}")
    if manifest_export_dir is not None:
        written = sum(1 for _, w, _ in manifest_results if w)
        skipped = sum(1 for _, w, _ in manifest_results if not w)
        _console.print(f"  [dim]manifests_written[/dim] {written} (skipped existing: {skipped})")
        _console.print(f"  [dim]manifest_dir[/dim]  {manifest_export_dir}")


@app.callback(invoke_without_command=True)
def _global_opts(
    ctx: typer.Context,
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Print version and exit",
    ),
) -> None:
    if version:
        typer.echo(f"recklock-discover {SCANNER_VERSION}")
        raise typer.Exit(0)
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help(), err=True)
        raise typer.Exit(0)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
